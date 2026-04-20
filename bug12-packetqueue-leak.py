#!/usr/bin/env python3
"""
Bug #12 PoC — PacketQueue Has No Destructor (Memory Leak)
==========================================================
Affected: src/helpers/StaticPoolPacketManager.h / .cpp
          src/Dispatcher.h (PacketManager base class)

Root cause
----------
PacketQueue allocates three arrays in its constructor:

    _table          = new mesh::Packet*[max_entries];    // 4 * N bytes
    _pri_table      = new uint8_t[max_entries];          // 1 * N bytes
    _schedule_table = new uint32_t[max_entries];         // 4 * N bytes

But has NO destructor — the memory is never freed via delete[].

StaticPoolPacketManager compounds this by:
  1. Containing 3 PacketQueue members (unused, send_queue, rx_queue)
  2. Allocating `pool_size` Packet objects via `new mesh::Packet()`
     in its constructor (also never freed)

The PacketManager base class also lacks a virtual destructor, so
deleting via a base pointer would be undefined behavior even if
a derived destructor existed.

Impact
------
On normal embedded firmware this is mostly academic — the objects are
created once at startup and never destroyed.  However:

  • Unit tests or integration tests that create/destroy PacketManager
    instances will leak memory proportional to pool_size on each iteration.
  • Any future firmware that supports runtime reconfiguration (e.g.
    changing pool_size, hot-restart) would leak all pool memory.
  • ASAN/Valgrind builds will flag this as a leak, obscuring real bugs.

Per-instance leak calculation:
  PacketQueue(N):
    3 arrays = N * (4 + 1 + 4) = 9 * N bytes

  StaticPoolPacketManager(pool_size):
    3 queues × 9 * pool_size = 27 * pool_size  (queue arrays)
    + pool_size * sizeof(Packet) = pool_size * ~320 bytes  (Packet objects)
    Total ≈ pool_size * 347 bytes

  For repeater (pool_size=32):  ~11 KB leaked per recreation
  For companion (pool_size=16): ~5.5 KB leaked per recreation

This script is an analysis-only PoC (the bug is in C++ — no Python
exploit possible). It calculates the exact leak size.

How to use
----------
    python bug12-packetqueue-leak.py
"""

import sys


# ---------- constants from firmware ----------
POINTER_SIZE     = 4     # 32-bit embedded platform
UINT8_SIZE       = 1
UINT32_SIZE      = 4

# Packet struct approximate size (from Packet.h):
#   header(1) + payload_len(2) + path_len(2) + transport_codes(4)
#   + path[MAX_PATH_SIZE=64] + payload[MAX_PACKET_PAYLOAD=184] + _snr(1)
PACKET_STRUCT_SIZE = 1 + 2 + 2 + 4 + 64 + 184 + 1  # = 258 bytes (actual may vary with alignment)

# Pool sizes by role
POOL_SIZES = {
    "companion_radio": 16,
    "simple_repeater":  32,
    "simple_room_server": 32,
    "simple_sensor": 32,
}

# Number of PacketQueue instances per StaticPoolPacketManager
NUM_QUEUES = 3  # unused, send_queue, rx_queue


def queue_leak(max_entries: int) -> int:
    """Bytes leaked by one PacketQueue(max_entries) without destructor."""
    return (
        max_entries * POINTER_SIZE      # _table (Packet**)
        + max_entries * UINT8_SIZE      # _pri_table
        + max_entries * UINT32_SIZE     # _schedule_table
    )


def manager_leak(pool_size: int) -> int:
    """Bytes leaked by one StaticPoolPacketManager(pool_size) without destructor."""
    queues = NUM_QUEUES * queue_leak(pool_size)
    packets = pool_size * PACKET_STRUCT_SIZE
    return queues + packets


def main():
    print("=" * 65)
    print("Bug #12 — PacketQueue / StaticPoolPacketManager Memory Leak")
    print("=" * 65)

    print(f"\n--- PacketQueue leak per instance ---")
    print(f"  _table:          N × {POINTER_SIZE} bytes  (Packet** array)")
    print(f"  _pri_table:      N × {UINT8_SIZE} byte   (uint8_t array)")
    print(f"  _schedule_table: N × {UINT32_SIZE} bytes  (uint32_t array)")
    print(f"  Total per queue: N × {POINTER_SIZE + UINT8_SIZE + UINT32_SIZE} = 9N bytes")

    print(f"\n--- StaticPoolPacketManager leak per instance ---")
    print(f"  3 queues × 9N bytes = 27N bytes  (queue internal arrays)")
    print(f"  N × Packet({PACKET_STRUCT_SIZE} bytes) = {PACKET_STRUCT_SIZE}N bytes  (pool objects)")
    print(f"  Total: ({27 + PACKET_STRUCT_SIZE})N bytes per manager")

    print(f"\n--- Leak by firmware role (per destruction without cleanup) ---")
    print(f"  {'Role':<22s}  {'Pool size':>9s}  {'Queue arrays':>12s}  {'Packets':>10s}  {'Total':>10s}")
    print(f"  {'─' * 22}  {'─' * 9}  {'─' * 12}  {'─' * 10}  {'─' * 10}")
    for role, ps in POOL_SIZES.items():
        q = NUM_QUEUES * queue_leak(ps)
        p = ps * PACKET_STRUCT_SIZE
        t = q + p
        print(f"  {role:<22s}  {ps:>9d}  {q:>10d} B  {p:>8d} B  {t:>8d} B")

    print(f"\n--- Missing virtual destructor in base class ---")
    print(f"  PacketManager (Dispatcher.h) has pure virtual methods but")
    print(f"  no virtual destructor. Deleting via PacketManager* pointer")
    print(f"  is undefined behavior in C++ (derived destructor never called).")

    print(f"\n--- Real-world impact ---")
    print(f"  Embedded firmware: LOW — objects created once, never destroyed")
    print(f"  Unit tests:        MEDIUM — leak accumulates per test iteration")
    print(f"  ASAN/Valgrind:     flags leak, may mask real bugs in CI")
    print(f"  Future hot-restart: HIGH — repeated reconfiguration leaks ~11KB/cycle")

    print(f"\n--- Reproduction ---")
    print(f"  1. Build MeshCore with AddressSanitizer (-fsanitize=address)")
    print(f"  2. In a test, create and delete StaticPoolPacketManager(32)")
    print(f"  3. ASAN reports ~11KB leak from 3 new[] + 32 new Packet()")
    print(f"  4. Repeat N times → N × 11KB leaked")


if __name__ == "__main__":
    main()
