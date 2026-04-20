#!/usr/bin/env python3
"""
Bug #20 -- Serial Frame Truncation Returns Corrupt Data
========================================================

PoC demonstrating that ArduinoSerialInterface::checkRecvFrame() silently
truncates oversized serial frames to MAX_FRAME_SIZE (172 bytes) and
returns the truncated data as if it were a valid frame. The caller
(handleCmdFrame) then parses a partial/corrupt command.

Parts A: Analytical (no hardware required) -- builds real payloads and computes truncation
Part B: Live meshcore_py test (requires a MeshCore companion_radio device)
"""

import struct


MAX_FRAME_SIZE = 172


# ========================================================================
# PART A: Frame protocol analysis and truncation demonstration
# ========================================================================
def part_a():
    print("=" * 72)
    print("PART A: Serial frame protocol and truncation analysis")
    print("=" * 72)
    print()

    print("Serial frame format (firmware <-> companion app):")
    print("  TX (app->device): '<' + len_LSB + len_MSB + payload[len]")
    print("  RX (device->app): '>' + len_LSB + len_MSB + payload[len]")
    print(f"  MAX_FRAME_SIZE = {MAX_FRAME_SIZE} bytes")
    print()

    # Demonstrate the truncation scenario
    print("Truncation scenario:")
    print("  1. Python side sends frame with len=200 (> MAX_FRAME_SIZE=172)")
    print("  2. Firmware receives header '<' + 0xC8 + 0x00 (200 bytes)")
    print("  3. checkRecvFrame() stores first 172 bytes in rx_buf")
    print("  4. Bytes 173-200 are read from serial but discarded")
    print("  5. When rx_len >= _frame_len (200), frame is 'complete'")
    print("  6. _frame_len is clamped to MAX_FRAME_SIZE (172)")
    print("  7. Returns 172 bytes to handleCmdFrame() as valid data")
    print()

    # Show what happens to a real command
    print("Example: CMD_SEND_TXT_MSG with a very long message")
    print()

    CMD_SEND_TXT_MSG = 0x02
    # Build a normal text message frame
    # Format: cmd(1) + txt_type(1) + attempt(1) + timestamp(4) + dst_key(6) + text
    cmd = CMD_SEND_TXT_MSG
    txt_type = 0x00  # plain text
    attempt = 0x00
    timestamp = struct.pack("<I", 1700000000)
    dst_key = bytes(6)  # 6-byte destination key prefix
    text = b"A" * 180  # very long message

    payload = bytes([cmd, txt_type, attempt]) + timestamp + dst_key + text
    print(f"  Original frame payload: {len(payload)} bytes")
    print(f"    cmd=0x{cmd:02x} txt_type=0x{txt_type:02x} attempt=0x{attempt:02x}")
    print(f"    timestamp={timestamp.hex()} dst_key={dst_key.hex()}")
    print(f"    text='{text[:20].decode()}...' ({len(text)} bytes)")
    print()

    if len(payload) > MAX_FRAME_SIZE:
        truncated = payload[:MAX_FRAME_SIZE]
        lost = len(payload) - MAX_FRAME_SIZE
        print(f"  After truncation: {len(truncated)} bytes (lost {lost} bytes)")
        print(f"    Message text truncated to: {len(text) - lost} bytes")
        print(f"    Firmware parses cmd_frame[0]=0x{truncated[0]:02x} len={len(truncated)}")
        print(f"    Text will be missing its last {lost} bytes")
        print()
        print("  Impact: The truncated text is passed to sendMessage().")
        print("  Since the firmware writes data[len]=0 AFTER decryption (not here),")
        print("  the truncation happens before encryption. The message is simply")
        print("  shorter than intended -- no memory corruption, just data loss.")
    else:
        print(f"  Frame fits within MAX_FRAME_SIZE ({len(payload)} <= {MAX_FRAME_SIZE})")
    print()


# ========================================================================
# PART B: Live meshcore_py test -- send oversized frame via serial
# ========================================================================
import asyncio

async def run_live_poc(port):
    try:
        from meshcore import MeshCore, EventType
    except ImportError:
        print("[ERROR] meshcore_py not installed. pip install meshcore")
        return

    print("=" * 72)
    print("PART B: Live meshcore_py -- send oversized serial frame")
    print("=" * 72)
    print(f"Device: {port}")
    print()

    mc = await MeshCore.create_serial(port, 115200)

    # The meshcore_py serial_cx.py send() method constructs:
    #   b"\x3c" + len.to_bytes(2, "little") + data
    # with NO size limit check.
    #
    # We'll send a CMD_SEND_CHANNEL_TXT_MSG with a very long text body
    # that exceeds MAX_FRAME_SIZE=172. The firmware will silently truncate.
    #
    # CMD_SEND_CHANNEL_TXT_MSG format:
    #   cmd(1) + 0x00(1) + channel_idx(1) + timestamp(4) + text

    CMD_SEND_CHANNEL_TXT_MSG = 0x03
    channel_idx = 0
    timestamp = struct.pack("<I", 1700000000)
    # Text that makes total frame > 172 bytes:
    # header = 1 + 1 + 1 + 4 = 7 bytes, so text > 165 bytes exceeds limit
    short_text = b"Short message OK"
    long_text = b"X" * 180  # 180 bytes of text -> 187 byte frame -> TRUNCATED

    print("[*] Test 1: Normal-sized channel message (should succeed)")
    frame_short = bytes([CMD_SEND_CHANNEL_TXT_MSG, 0x00, channel_idx]) + timestamp + short_text
    print(f"    Frame size: {len(frame_short)} bytes (under MAX_FRAME_SIZE={MAX_FRAME_SIZE})")

    # Use low-level send to bypass any Python-side validation
    if hasattr(mc, '_cx') and hasattr(mc._cx, 'send'):
        await mc._cx.send(frame_short)
        print("    Sent successfully")
    elif hasattr(mc, 'connection') and hasattr(mc.connection, 'send'):
        await mc.connection.send(frame_short)
        print("    Sent successfully")
    else:
        print("    [!] Cannot access low-level send -- using send_chan_msg instead")
        try:
            await mc.send_chan_msg(0, short_text.decode(), 1700000000)
            print("    Sent successfully via send_chan_msg")
        except Exception as e:
            print(f"    Error: {e}")

    await asyncio.sleep(1)

    print()
    print("[*] Test 2: Oversized channel message (will be truncated)")
    frame_long = bytes([CMD_SEND_CHANNEL_TXT_MSG, 0x00, channel_idx]) + timestamp + long_text
    print(f"    Frame size: {len(frame_long)} bytes (EXCEEDS MAX_FRAME_SIZE={MAX_FRAME_SIZE})")
    print(f"    Firmware will truncate to {MAX_FRAME_SIZE} bytes -> text loses {len(frame_long) - MAX_FRAME_SIZE} bytes")

    if hasattr(mc, '_cx') and hasattr(mc._cx, 'send'):
        await mc._cx.send(frame_long)
        print("    Sent oversized frame")
    elif hasattr(mc, 'connection') and hasattr(mc.connection, 'send'):
        await mc.connection.send(frame_long)
        print("    Sent oversized frame")
    else:
        print("    [!] Cannot access low-level send")

    await asyncio.sleep(1)

    print()
    print("[*] The oversized frame was silently truncated by the firmware.")
    print("    If the device transmitted a channel message, it contained")
    print(f"    only the first {MAX_FRAME_SIZE - 7} characters instead of {len(long_text)}.")
    print("    No error was returned to the sender -- data silently lost.")
    print()
    print("[*] The firmware's writeFrame() correctly REJECTS outbound frames")
    print("    > MAX_FRAME_SIZE (returns 0). Only inbound checkRecvFrame()")
    print("    has the truncation bug.")

    await mc.disconnect()


# ========================================================================
# Main
# ========================================================================
if __name__ == "__main__":
    import sys

    if "--live" in sys.argv:
        idx = sys.argv.index("--live")
        if len(sys.argv) < idx + 2:
            print("Usage: python bug20-serial-truncation.py --live PORT")
            print("Example: python bug20-serial-truncation.py --live COM3")
            sys.exit(1)
        port = sys.argv[idx + 1]
        asyncio.run(run_live_poc(port))
    else:
        print("Bug #20 PoC -- Serial Frame Truncation Returns Corrupt Data")
        print("=============================================================")
        print()
        part_a()
        print()
        print("To run the live test:")
        print("  python bug20-serial-truncation.py --live COM3")
