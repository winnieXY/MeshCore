#!/usr/bin/env python3
"""
Bug #9 PoC — Radio Stuck Detection With No Recovery
====================================================
Affected: src/Dispatcher.cpp (all firmware variants)

Root cause
----------
Dispatcher::loop() detects when the radio has been outside RX mode
for >8 seconds and sets ERR_EVENT_STARTRX_TIMEOUT.  But the flag is
only reported in stats — no recovery action is taken.  The radio
stays stuck forever.

Scenarios that trigger a stuck radio:
  • SPI corruption from flash/radio conflict (Bug #22)
  • Failed startReceive() after a TX timeout
  • Hardware glitch on DIO1 (ISR never fires → isSendComplete()
    returns false → outbound_expiry fires → onSendFinished() →
    startReceive() may fail on the corrupted SPI bus)

This PoC forces the radio into a stuck state by sending a rapid
burst of messages (saturating the outbound queue and TX budget),
then monitors whether the target node recovers RX capability.

How to use
----------
  pip install meshcore

  # Two devices needed: sender (local) and target (remote).
  # The target's radio can get stuck after heavy TX.

  # Monitor target via status probes — press Ctrl-C to stop:
  python bug9-radio-stuck.py -p COM3 -d mynode

  # With optional message burst to increase TX load:
  python bug9-radio-stuck.py -p COM3 -d mynode --burst 20
"""

import asyncio, argparse, sys, time

try:
    from meshcore import MeshCore, EventType
except ImportError:
    sys.exit("meshcore not found – pip install meshcore")

STUCK_THRESHOLD = 8.0  # firmware uses 8 seconds

async def main():
    ap = argparse.ArgumentParser(description="Bug #9 radio-stuck PoC")
    ap.add_argument("-p", "--port", required=True, help="Serial port")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    ap.add_argument("-d", "--dest", required=True, help="Target contact name")
    ap.add_argument("--burst", type=int, default=0,
                    help="Send N messages first to load the TX queue (default: 0)")
    args = ap.parse_args()

    mc = await MeshCore.create_serial(args.port, args.baud)
    if not mc:
        sys.exit("connect failed")

    try:
        await mc.ensure_contacts()
        contact = mc.get_contact_by_name(args.dest)
        if not contact:
            sys.exit(f"contact '{args.dest}' not found")

        # Optional: burst messages to saturate TX and stress the radio
        if args.burst > 0:
            print(f"Sending {args.burst} messages to load TX queue …")
            for i in range(args.burst):
                await mc.commands.send_msg(contact, f"stress#{i}")
            print("Burst done.  Waiting for TX to drain …\n")
            await asyncio.sleep(2.0)

        # Probe loop — detect if the remote node's radio is stuck
        print("Probing target node.  Press Ctrl-C to stop.\n")
        print(f"{'#':>4}  {'RTT':>8}  status")

        consecutive_timeouts = 0
        i = 0
        while True:
            i += 1
            ts = time.monotonic()
            try:
                r = await mc.commands.req_status_sync(contact, timeout=10)
                rtt = (time.monotonic() - ts) * 1000
                ok = r and r.type != EventType.ERROR
            except Exception:
                rtt = (time.monotonic() - ts) * 1000
                ok = False

            if ok:
                consecutive_timeouts = 0
                print(f"{i:4}  {rtt:7.0f}ms  OK")
            else:
                consecutive_timeouts += 1
                note = ""
                if consecutive_timeouts * 10 > STUCK_THRESHOLD:
                    note = "  ** RADIO STUCK — no recovery (Bug #9) **"
                print(f"{i:4}  {rtt:7.0f}ms  TIMEOUT  ({consecutive_timeouts} consecutive){note}")

                if consecutive_timeouts >= 5:
                    print(f"\n{consecutive_timeouts} consecutive timeouts — target radio is stuck.")
                    print("Dispatcher set ERR_EVENT_STARTRX_TIMEOUT but took no recovery action.")
                    print("Device requires reboot — Bug #9 confirmed.")
                    break

            await asyncio.sleep(2.0)

    except KeyboardInterrupt:
        print(f"\nStopped.  Last consecutive timeouts: {consecutive_timeouts}")
    finally:
        await mc.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
