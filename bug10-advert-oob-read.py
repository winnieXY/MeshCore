#!/usr/bin/env python3
"""
Bug #10 PoC — AdvertDataParser Out-of-Bounds Read
==================================================
Affected: src/helpers/AdvertDataHelpers.cpp — AdvertDataParser constructor

Root cause
----------
The AdvertDataParser constructor reads flag-indicated optional fields
(lat/lon: 8 bytes, feat1: 2 bytes, feat2: 2 bytes) using memcpy()
BEFORE checking whether app_data_len is large enough.  The bounds
check `if (app_data_len >= i)` appears only AFTER all the reads have
already been performed.

A crafted advertisement packet with app_data_len == 1 and the flags
byte set to 0x70 (ADV_LATLON_MASK | ADV_FEAT1_MASK | ADV_FEAT2_MASK)
causes 4 memcpy() calls that read a total of 12 bytes past the 1-byte
buffer:

  memcpy(&_lat,    &app_data[1],  4);   // OOB read [1..4]
  memcpy(&_lon,    &app_data[5],  4);   // OOB read [5..8]
  memcpy(&_extra1, &app_data[9],  2);   // OOB read [9..10]
  memcpy(&_extra2, &app_data[11], 2);   // OOB read [11..12]

Although the parser returns _valid == false and callers discard the
result, the OOB reads have ALREADY happened, reading stack or heap
data adjacent to the packet payload buffer.

On microcontrollers this typically reads:
  - Adjacent stack variables (saved registers, return addresses)
  - Adjacent heap allocations (packet pool contents)

On some architectures (ESP32 with memory protection / nRF52 with MPU),
crossing a region boundary may trigger a bus fault / HardFault → reboot.

Attack surface
--------------
Advertisement packets require a valid ed25519 signature, so a pure
outsider cannot forge them.  However:
  • Any enrolled node can sign its own malformed adverts
  • A compromised node can target all receivers in range
  • The signature covers the malformed app_data, so it passes verification
  • The OOB read is triggered on EVERY receiver that processes the advert

This PoC demonstrates the vulnerability via packet analysis only.
A real exploit would require a modified firmware node to sign and
broadcast the malformed packet.

How to use
----------
1. Analysis only (no device needed):
     python bug10-advert-oob-read.py --analyze

2. Monitor adverts on a connected device (observe malformed packets):
     python bug10-advert-oob-read.py -p COM3 --monitor
"""

import asyncio
import argparse
import struct
import sys

try:
    from meshcore import MeshCore, EventType
except ImportError:
    sys.exit("meshcore package not found – pip install meshcore")


# ---------- protocol constants (must match firmware) ----------
PUB_KEY_SIZE          = 32
SIGNATURE_SIZE        = 64
MAX_PACKET_PAYLOAD    = 184
MAX_ADVERT_DATA_SIZE  = 32

# Advert flag bits
ADV_TYPE_MASK         = 0x0F
ADV_LATLON_MASK       = 0x10   # 8 bytes: 4-byte lat + 4-byte lon
ADV_FEAT1_MASK        = 0x20   # 2 bytes
ADV_FEAT2_MASK        = 0x40   # 2 bytes
ADV_NAME_MASK         = 0x80   # variable length name

# Advert types
ADV_TYPE_NAMES = {0: "NONE", 1: "CHAT", 2: "REPEATER", 3: "ROOM", 4: "SENSOR"}

# Fixed header before app_data in advert payload
ADVERT_HEADER_SIZE    = PUB_KEY_SIZE + 4 + SIGNATURE_SIZE  # 32 + 4 + 64 = 100


def parse_flags(flags: int) -> dict:
    """Decode advert flags byte into human-readable components."""
    return {
        "type": ADV_TYPE_NAMES.get(flags & ADV_TYPE_MASK, f"UNKNOWN({flags & ADV_TYPE_MASK})"),
        "has_latlon": bool(flags & ADV_LATLON_MASK),
        "has_feat1": bool(flags & ADV_FEAT1_MASK),
        "has_feat2": bool(flags & ADV_FEAT2_MASK),
        "has_name": bool(flags & ADV_NAME_MASK),
    }


def expected_min_length(flags: int) -> int:
    """Calculate minimum app_data length required for the given flags."""
    n = 1  # flags byte
    if flags & ADV_LATLON_MASK:
        n += 8
    if flags & ADV_FEAT1_MASK:
        n += 2
    if flags & ADV_FEAT2_MASK:
        n += 2
    # name is variable — 0 bytes is valid if ADV_NAME_MASK is not set
    return n


def analyze():
    """Demonstrate the OOB read for all flag combinations with short buffers."""
    print("=" * 70)
    print("Bug #10 — AdvertDataParser OOB Read Analysis")
    print("=" * 70)

    print(f"\nPacket layout:")
    print(f"  pkt->payload[0..{PUB_KEY_SIZE-1}]  : public key ({PUB_KEY_SIZE} bytes)")
    print(f"  pkt->payload[{PUB_KEY_SIZE}..{PUB_KEY_SIZE+3}]  : timestamp (4 bytes)")
    print(f"  pkt->payload[{PUB_KEY_SIZE+4}..{ADVERT_HEADER_SIZE-1}] : signature ({SIGNATURE_SIZE} bytes)")
    print(f"  pkt->payload[{ADVERT_HEADER_SIZE}..end]  : app_data (0..{MAX_ADVERT_DATA_SIZE} bytes)")

    print(f"\n--- Vulnerability: OOB reads in AdvertDataParser constructor ---")
    print(f"  The flags byte is at app_data[0]. Optional fields follow:")
    print(f"    ADV_LATLON_MASK (0x10) → memcpy 8 bytes (lat + lon)")
    print(f"    ADV_FEAT1_MASK  (0x20) → memcpy 2 bytes")
    print(f"    ADV_FEAT2_MASK  (0x40) → memcpy 2 bytes")
    print(f"  ALL reads happen BEFORE the bounds check at line 47.")

    # Enumerate dangerous flag combinations
    print(f"\n--- Flag combinations with 1-byte app_data (worst case) ---")
    print(f"  {'Flags':>5s}  {'Indicated fields':<35s}  {'Min len':>7s}  {'OOB read':>8s}")
    print(f"  {'─'*5}  {'─'*35}  {'─'*7}  {'─'*8}")

    dangerous = []
    for flags in range(0x10, 0x80):  # only care about field flags
        if not (flags & (ADV_LATLON_MASK | ADV_FEAT1_MASK | ADV_FEAT2_MASK)):
            continue
        info = parse_flags(flags)
        fields = []
        if info["has_latlon"]: fields.append("lat/lon(8B)")
        if info["has_feat1"]: fields.append("feat1(2B)")
        if info["has_feat2"]: fields.append("feat2(2B)")
        min_len = expected_min_length(flags)
        oob = min_len - 1  # 1 byte provided
        dangerous.append((flags, fields, min_len, oob))
        print(f"  0x{flags:02x}   {' + '.join(fields):<35s}  {min_len:>7d}  {oob:>8d}")

    # Worst case
    worst = max(dangerous, key=lambda x: x[3])
    print(f"\n--- Worst case: flags=0x{worst[0]:02x} ---")
    print(f"  Claimed fields : {' + '.join(worst[1])}")
    print(f"  Min app_data   : {worst[2]} bytes")
    print(f"  Actual provided: 1 byte (just the flags)")
    print(f"  OOB read       : {worst[3]} bytes past buffer")

    print(f"\n--- Malicious packet construction ---")
    print(f"  payload_len = {ADVERT_HEADER_SIZE + 1}  (100 header + 1 app_data)")
    print(f"  app_data[0] = 0x{worst[0]:02x}")
    print(f"  Parser performs:")
    offset = 1
    if worst[0] & ADV_LATLON_MASK:
        print(f"    memcpy(&_lat, &app_data[{offset}], 4)  →  reads [{offset}..{offset+3}]  OOB by {offset+3} bytes")
        offset += 4
        print(f"    memcpy(&_lon, &app_data[{offset}], 4)  →  reads [{offset}..{offset+3}]  OOB by {offset+3} bytes")
        offset += 4
    if worst[0] & ADV_FEAT1_MASK:
        print(f"    memcpy(&_extra1, &app_data[{offset}], 2)  →  reads [{offset}..{offset+1}]  OOB by {offset+1} bytes")
        offset += 2
    if worst[0] & ADV_FEAT2_MASK:
        print(f"    memcpy(&_extra2, &app_data[{offset}], 2)  →  reads [{offset}..{offset+1}]  OOB by {offset+1} bytes")
        offset += 2

    print(f"\n--- Impact ---")
    print(f"  • OOB reads happen unconditionally during constructor")
    print(f"  • _valid is set to false → caller checks isValid() and discards")
    print(f"  • BUT the reads already happened — memory corruption / fault possible")
    print(f"  • On ESP32: may read IRAM/flash-mapped region → LoadProhibited exception → reboot")
    print(f"  • On nRF52: may cross MPU region → HardFault → reboot")
    print(f"  • Attacks every node in radio range that processes the advert")

    print(f"\n--- Signature requirement ---")
    print(f"  Advertisement packets must carry a valid ed25519 signature.")
    print(f"  The attacker must own a valid key pair (= be an enrolled node).")
    print(f"  The signature covers: pub_key + timestamp + app_data (1 byte).")
    print(f"  Since the attacker signs their own packet, this is trivially satisfied.")


async def monitor(port: str, baud: int):
    """Connect to device and monitor incoming adverts, flagging malformed ones."""
    mc = await MeshCore.create_serial(port, baud, debug=False)
    if mc is None:
        sys.exit("Could not connect to device")

    print("[*] Monitoring incoming advertisements...")
    print("[*] Press Ctrl-C to stop\n")

    def on_event(event):
        if event.type == EventType.CONTACT_CONNECTED or event.type == EventType.CONTACT_DISCONNECTED:
            name = getattr(event, 'contact_name', '?')
            print(f"  [{event.type.name}] {name}")

    mc.on(EventType.CONTACT_CONNECTED, on_event)
    mc.on(EventType.CONTACT_DISCONNECTED, on_event)

    try:
        # Get current contacts to show baseline
        await mc.ensure_contacts()
        contacts = mc.contacts if hasattr(mc, 'contacts') else []
        print(f"[*] Known contacts: {len(contacts)}")
        for c in contacts:
            name = getattr(c, 'name', '?')
            ctype = getattr(c, 'type', -1)
            print(f"    {name} (type={ctype})")
        print()

        print("[*] Listening for events... (adverts are processed internally)")
        print("[*] A malformed advert would cause an OOB read BEFORE any")
        print("[*] event is emitted — the crash/fault happens in the firmware,")
        print("[*] not visible here unless the device reboots.")
        print()

        # Keep running
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    finally:
        await mc.disconnect()


async def main() -> None:
    ap = argparse.ArgumentParser(description="Bug #10 — AdvertDataParser OOB read PoC")
    ap.add_argument("-p", "--port", default=None, help="Serial port (e.g. COM3)")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    ap.add_argument("--analyze", action="store_true",
                    help="Print vulnerability analysis (no device needed)")
    ap.add_argument("--monitor", action="store_true",
                    help="Monitor adverts on connected device")
    args = ap.parse_args()

    if args.analyze:
        analyze()
        return

    if args.monitor:
        if not args.port:
            sys.exit("--port is required for --monitor")
        await monitor(args.port, args.baud)
        return

    # Default: show analysis
    analyze()


if __name__ == "__main__":
    asyncio.run(main())
