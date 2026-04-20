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
collision window.  20 clients x 136 B = 2720 B of flash I/O.

How to use
----------
  pip install meshcore
  python bug22-flash-hang.py -p COM3 -d myrepeater --pwd secret

  To widen the flash/SPI collision window, use --flood-saves N
  to trigger N rapid ACL saves per cycle via "setperm" CLI commands:
  python bug22-flash-hang.py -p COM3 -d myrepeater --pwd secret --flood-saves 10

Logs in, probes for ~12s, then logs out and repeats in a loop
until the hang occurs or Ctrl-C is pressed.
"""

import asyncio, argparse, sys, time, os

try:
    from meshcore import MeshCore, EventType
except ImportError:
    sys.exit("meshcore not found – pip install meshcore")

SAVE_DELAY = 5.0  # firmware LAZY_CONTACTS_WRITE_DELAY (seconds)

async def run_cycle(mc, contact, pwd, cycle, flood_saves):
    """Run one login → probe → logout cycle.  Returns True if hang detected."""
    print(f"\n{'='*50}")
    print(f"Cycle {cycle}: logging in ...")
    r = await mc.commands.send_login_sync(contact, pwd, min_timeout=10)
    if not r or r.type == EventType.ERROR:
        print(f"  Login failed: {r}")
        return False

    t0 = time.monotonic()
    print(f"  Login OK.  acl.save() expected at ~{SAVE_DELAY:.0f}s.  Probing ...")

    # If --flood-saves is set, hammer "setperm" with random pubkeys
    # to force the repeater to write the ACL to flash repeatedly.
    # Each setperm that matches an ACL entry resets dirty_contacts_expiry,
    # triggering another acl.save() 5s later.  Sending many in quick
    # succession causes overlapping flash writes, widening the SPI
    # collision window.
    if flood_saves > 0:
        print(f"  Flooding {flood_saves} setperm commands to widen flash collision window...")
        for i in range(flood_saves):
            # Generate a random 32-byte pubkey hex.  If it doesn't match
            # an existing ACL entry, setperm returns an error but is harmless.
            # If it DOES match (unlikely for random keys), it sets permissions.
            # Either way, we also use the companion's own key to guarantee
            # at least one match that dirties the ACL.
            pub_hex = contact.get("public_key", "")
            if pub_hex:
                # Alternate: use actual contact key (guaranteed ACL hit) and
                # random keys (add noise / stress the flash path)
                if i % 2 == 0:
                    key_hex = pub_hex[:64]  # real key — will match, dirty ACL
                    perm = "3"  # admin
                else:
                    key_hex = os.urandom(32).hex()  # random — won't match, no-op
                    perm = "1"
            else:
                key_hex = os.urandom(32).hex()
                perm = "1"

            try:
                await mc.commands.send_cmd(contact, f"setperm {key_hex} {perm}")
            except Exception:
                pass
            # Small delay so the firmware processes each command
            await asyncio.sleep(0.3)
        print(f"  Done. Each matching setperm resets the 5s save timer.")
        print(f"  Multiple acl.save() calls will follow in quick succession.")

    CONSEC_REQUIRED = 3  # need 3 consecutive timeouts to confirm permanent hang
    consec_timeouts = 0
    hung = False
    for i in range(20):
        await asyncio.sleep(1.5)
        t = time.monotonic() - t0
        ts = time.monotonic()
        r = None
        try:
            r = await mc.commands.req_status_sync(contact, timeout=12)
            rtt = (time.monotonic() - ts) * 1000
            # req_status_sync returns the payload dict on success, None on timeout
            ok = r is not None
        except Exception as e:
            rtt = (time.monotonic() - ts) * 1000
            ok = False

        # Build informative tag
        if ok:
            tag = f"OK (rssi={r.get('last_rssi','?')}, recv={r.get('nb_recv','?')})"
        else:
            tag = "NO RESPONSE"

        note = " <-- acl.save() window" if 3.5 < t < 8.0 else ""
        if not ok:
            consec_timeouts += 1
            if consec_timeouts >= CONSEC_REQUIRED:
                note += f"  ** PERMANENT HANG ({consec_timeouts} consecutive) **"
            else:
                note += f"  (fail {consec_timeouts}/{CONSEC_REQUIRED})"
        else:
            if consec_timeouts > 0:
                note += f"  (recovered after {consec_timeouts} fail(s))"
            consec_timeouts = 0

        print(f"  {i+1:3}  {t:5.1f}s  {rtt:7.0f}ms  {tag}{note}")

        if consec_timeouts >= CONSEC_REQUIRED:
            hung = True
            break

    if hung:
        print(f"\n*** Cycle {cycle}: Repeater permanently hung after acl.save() -- Bug #22 confirmed! ***")
        print(f"    {CONSEC_REQUIRED} consecutive probes timed out. Radio is dead.")
        print("Device requires reboot to recover.")
        return True

    # Logout so next login dirties the ACL again
    print(f"  Cycle {cycle}: no hang -- logging out ...")
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
    ap.add_argument("--flood-saves", type=int, default=0, metavar="N",
                    help="Send N 'setperm' CLI commands per cycle to trigger "
                         "repeated acl.save() flash writes (widens SPI collision window)")
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
            if await run_cycle(mc, contact, args.pwd, cycle, args.flood_saves):
                break
    except KeyboardInterrupt:
        print(f"\nStopped after {cycle} cycles — hang did not occur.")
    finally:
        await mc.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
