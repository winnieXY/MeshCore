#!/usr/bin/env python3
"""
Bug #22 PoC — Permanent Radio Hang from Flash/SPI Conflict on Login
===================================================================
Affected: simple_repeater, simple_room_server, simple_sensor (nRF52)

Root cause
----------
On nRF52 the SoftDevice owns both the BLE radio and flash controller.
When acl.save() calls _fs->remove() / file.write(), the SoftDevice
halts the CPU for flash page erase/program (~85ms per page).  If the
SX1262 LoRa radio has an active SPI transaction at that moment, the
SPI bus is left corrupted (CS held low, MOSI mid-byte).  The radio
NEVER recovers — permanent hang until reboot.

Every login dirties the ACL.  5 seconds later acl.save() fires.
Risk scales with ACL size: more clients = more flash writes = wider
collision window.  20 clients × 136 B = 2720 B of flash I/O.

How to use
----------
  pip install meshcore
  python bug22-flash-hang.py -p COM3 -d myrepeater --pwd secret

Logs in, probes for ~12s, then logs out and repeats in a loop
until the hang occurs or Ctrl-C is pressed.
"""

import asyncio, argparse, sys, time

try:
    from meshcore import MeshCore, EventType
except ImportError:
    sys.exit("meshcore not found – pip install meshcore")

SAVE_DELAY = 5.0  # firmware LAZY_CONTACTS_WRITE_DELAY (seconds)

async def run_cycle(mc, contact, pwd, cycle):
    """Run one login → probe → logout cycle.  Returns True if hang detected."""
    print(f"\n{'='*50}")
    print(f"Cycle {cycle}: logging in …")
    r = await mc.commands.send_login_sync(contact, pwd, min_timeout=10)
    if not r or r.type == EventType.ERROR:
        print(f"  Login failed: {r}")
        return False

    t0 = time.monotonic()
    print(f"  Login OK.  acl.save() expected at ~{SAVE_DELAY:.0f}s.  Probing …")

    hung = False
    for i in range(12):
        await asyncio.sleep(1.0)
        t = time.monotonic() - t0
        ts = time.monotonic()
        try:
            r = await mc.commands.req_status_sync(contact, timeout=8)
            rtt = (time.monotonic() - ts) * 1000
            ok = r and r.type != EventType.ERROR
        except Exception:
            rtt = (time.monotonic() - ts) * 1000
            ok = False

        tag = "OK" if ok else "TIMEOUT"
        note = " <-- acl.save()" if abs(t - SAVE_DELAY) < 1.5 else ""
        if not ok:
            note += "  ** HANG **"
        print(f"  {i+1:3}  {t:5.1f}s  {rtt:7.0f}ms  {tag}{note}")

        if not ok and t > SAVE_DELAY:
            hung = True
            break

    if hung:
        print(f"\n*** Cycle {cycle}: Repeater hung after acl.save() — Bug #22 confirmed! ***")
        print("Device requires reboot to recover.")
        return True

    # Logout so next login dirties the ACL again
    print(f"  Cycle {cycle}: no hang — logging out …")
    try:
        await mc.commands.send_logout(contact)
    except Exception:
        pass
    await asyncio.sleep(1.0)
    return False

async def main():
    ap = argparse.ArgumentParser(description="Bug #22 flash-hang PoC (loops until hang or Ctrl-C)")
    ap.add_argument("-p", "--port", required=True, help="Serial port")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    ap.add_argument("-d", "--dest", required=True, help="Repeater contact name")
    ap.add_argument("--pwd", required=True, help="Repeater password")
    args = ap.parse_args()

    mc = await MeshCore.create_serial(args.port, args.baud)
    if not mc:
        sys.exit("connect failed")

    try:
        await mc.ensure_contacts()
        contact = mc.get_contact_by_name(args.dest)
        if not contact:
            sys.exit(f"contact '{args.dest}' not found")

        print("Cycling login/logout until hang occurs.  Press Ctrl-C to stop.")
        cycle = 0
        while True:
            cycle += 1
            if await run_cycle(mc, contact, args.pwd, cycle):
                break
    except KeyboardInterrupt:
        print(f"\nStopped after {cycle} cycles — hang did not occur.")
    finally:
        await mc.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
