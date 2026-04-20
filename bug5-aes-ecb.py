#!/usr/bin/env python3
"""
Bug #5 -- AES-128 ECB Mode Leaks Plaintext Patterns
=====================================================

PoC demonstrating that MeshCore's AES-128-ECB encryption (Utils.cpp) leaks
plaintext structure because identical plaintext blocks always produce
identical ciphertext blocks, and no IV/nonce is used.

Parts A-C: Analytical (no hardware required, uses pycryptodome)
Part D: Live meshcore_py two-device test (requires two MeshCore devices)
"""

import struct
import hashlib
import hmac
import os

# ---------------------------------------------------------------------------
# Helpers: replicate MeshCore's encrypt() and encryptThenMAC() in Python
# ---------------------------------------------------------------------------
try:
    from Crypto.Cipher import AES as AES_LIB
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

CIPHER_KEY_SIZE = 16
CIPHER_BLOCK_SIZE = 16
CIPHER_MAC_SIZE = 2
PUB_KEY_SIZE = 32


def meshcore_ecb_encrypt(key_16: bytes, plaintext: bytes, random_pad: bool = False) -> bytes:
    """Replica of Utils::encrypt() -- AES-128-ECB.
    random_pad=False: original (zero-padded), random_pad=True: patched (random-padded)."""
    assert len(key_16) == CIPHER_KEY_SIZE
    cipher = AES_LIB.new(key_16, AES_LIB.MODE_ECB)
    out = b""
    i = 0
    while i + 16 <= len(plaintext):
        out += cipher.encrypt(plaintext[i:i+16])
        i += 16
    if i < len(plaintext):
        remainder = len(plaintext) - i
        if random_pad:
            pad = os.urandom(16 - remainder)
        else:
            pad = b"\x00" * (16 - remainder)
        block = plaintext[i:] + pad
        out += cipher.encrypt(block)
    return out


def meshcore_encrypt_then_mac(shared_secret_32: bytes, plaintext: bytes) -> bytes:
    """Exact replica of Utils::encryptThenMAC()."""
    key_16 = shared_secret_32[:CIPHER_KEY_SIZE]
    ct = meshcore_ecb_encrypt(key_16, plaintext)
    mac = hmac.new(shared_secret_32, ct, hashlib.sha256).digest()[:CIPHER_MAC_SIZE]
    return mac + ct


# ========================================================================
# PART A: Deterministic ciphertext -- identical messages produce identical
#         encrypted packets, enabling repeated-message detection.
# ========================================================================
def part_a():
    print("=" * 72)
    print("PART A: Deterministic ciphertext (same plaintext -> same ciphertext)")
    print("=" * 72)
    if not HAS_CRYPTO:
        print("[SKIP] pycryptodome not installed (pip install pycryptodome)")
        return

    # Simulate a channel shared secret (32 bytes) and AES key (first 16)
    shared_secret = bytes.fromhex(
        "0123456789abcdef0123456789abcdef"
        "fedcba9876543210fedcba9876543210"
    )

    # Simulate a group message plaintext:
    # [timestamp(4)] [type=0x00(1)] ["Alice: hello\0"]
    timestamp = struct.pack("<I", 1700000000)
    plaintext = timestamp + b"\x00" + b"Alice: hello\x00"

    ct1 = meshcore_encrypt_then_mac(shared_secret, plaintext)
    ct2 = meshcore_encrypt_then_mac(shared_secret, plaintext)

    print(f"Plaintext ({len(plaintext)} bytes): {plaintext.hex()}")
    print(f"Ciphertext 1: {ct1.hex()}")
    print(f"Ciphertext 2: {ct2.hex()}")
    print(f"Identical?    {ct1 == ct2}")
    print()
    print("[!] An attacker with a LoRa SDR who captures both transmissions")
    print("    can determine, WITHOUT the key, that the same message was sent")
    print("    twice. This leaks conversation patterns and enables replay.")
    print()


# ========================================================================
# PART B: ECB penguin -- repeated 16-byte blocks in plaintext produce
#         repeated ciphertext blocks, leaking internal structure.
# ========================================================================
def part_b():
    print("=" * 72)
    print("PART B: ECB block repetition (identical blocks -> identical ciphertext)")
    print("=" * 72)
    if not HAS_CRYPTO:
        print("[SKIP] pycryptodome not installed")
        return

    key = os.urandom(16)
    cipher = AES_LIB.new(key, AES_LIB.MODE_ECB)

    # Message with two identical 16-byte blocks
    block_a = b"AAAAAAAAAAAAAAAA"  # 16 bytes
    block_b = b"BBBBBBBBBBBBBBBB"  # 16 bytes

    # Pattern: A | B | A  (48 bytes, 3 blocks)
    plaintext = block_a + block_b + block_a
    ct = meshcore_ecb_encrypt(key, plaintext)

    ct_blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    print(f"Plaintext blocks:")
    print(f"  Block 0: {block_a.hex()}  ('A' * 16)")
    print(f"  Block 1: {block_b.hex()}  ('B' * 16)")
    print(f"  Block 2: {block_a.hex()}  ('A' * 16)")
    print()
    print(f"Ciphertext blocks:")
    for i, blk in enumerate(ct_blocks):
        print(f"  Block {i}: {blk.hex()}")
    print()
    print(f"Block 0 == Block 2?  {ct_blocks[0] == ct_blocks[2]}")
    print(f"Block 0 == Block 1?  {ct_blocks[0] == ct_blocks[1]}")
    print()
    print("[!] Identical plaintext blocks produce identical ciphertext blocks.")
    print("    An observer can infer which parts of the message are the same")
    print("    without knowing a single byte of the plaintext or key.")
    print()


# ========================================================================
# PART C: Known-structure codebook -- attacker can correlate messages from
#         the predictable first-block structure (timestamp + type byte).
# ========================================================================
def part_c():
    print("=" * 72)
    print("PART C: Known-structure first-block correlation")
    print("=" * 72)
    if not HAS_CRYPTO:
        print("[SKIP] pycryptodome not installed")
        return

    shared_secret = os.urandom(32)
    key = shared_secret[:16]
    cipher = AES_LIB.new(key, AES_LIB.MODE_ECB)

    # Group messages use: [ts(4)] [type=0x00(1)] [sender_name: text...]
    # The first 5 bytes are structured. If two messages are sent at a
    # similar time (same 4-byte unix timestamp), and the sender name
    # plus first ~10 chars of text match, the entire first 16-byte
    # block is identical.

    ts = struct.pack("<I", 1700000000)

    # Same sender, same beginning of message, same second
    msg1_plain = ts + b"\x00" + b"Alice: hel"  # 15 bytes -> padded to 16
    msg2_plain = ts + b"\x00" + b"Alice: hel"  # identical first block
    # ...but different continuations
    msg1_full = ts + b"\x00" + b"Alice: hello world, how are you?\x00"
    msg2_full = ts + b"\x00" + b"Alice: hello world, nice day!\x00"

    ct1 = meshcore_ecb_encrypt(key, msg1_full)
    ct2 = meshcore_ecb_encrypt(key, msg2_full)

    ct1_b = [ct1[i:i+16] for i in range(0, len(ct1), 16)]
    ct2_b = [ct2[i:i+16] for i in range(0, len(ct2), 16)]

    print("Message 1 plaintext (hex):")
    for i, b in enumerate([msg1_full[j:j+16] for j in range(0, len(msg1_full), 16)]):
        print(f"  Block {i}: {b.hex()}  {repr(b)}")
    print("Message 2 plaintext (hex):")
    for i, b in enumerate([msg2_full[j:j+16] for j in range(0, len(msg2_full), 16)]):
        print(f"  Block {i}: {b.hex()}  {repr(b)}")
    print()

    print("Ciphertext block comparison:")
    for i in range(max(len(ct1_b), len(ct2_b))):
        b1 = ct1_b[i] if i < len(ct1_b) else b"(none)"
        b2 = ct2_b[i] if i < len(ct2_b) else b"(none)"
        match = "MATCH" if b1 == b2 else "differ"
        print(f"  Block {i}: {match}")
        if b1 == b2:
            print(f"           ct1: {b1.hex()}")
            print(f"           ct2: {b2.hex()}")

    print()
    print("[!] Messages from the same sender at the same timestamp share")
    print("    identical first ciphertext block(s). An attacker who sees")
    print("    the same first block in two packets knows they came from")
    print("    the same sender in the same second -- even without the key.")
    print()


# ========================================================================
# PART D: Live meshcore_py two-device PoC
# ========================================================================
import asyncio

async def run_live_poc(sender_port, monitor_port):
    # Requires: two MeshCore devices (one sender, one monitor) on the same
    # channel. Run as: python bug5-aes-ecb.py --live SENDER_PORT MONITOR_PORT
    #
    # The script:
    #   1. Connects to both devices via serial
    #   2. Subscribes to RX_LOG_DATA on the monitor device
    #   3. Sends the same channel message with the same timestamp TWICE
    #      from the sender device
    #   4. Captures ciphertext payloads on the monitor
    #   5. Compares captured payloads -- in ECB mode they are IDENTICAL
    import time

    try:
        from meshcore import MeshCore, EventType
    except ImportError:
        print("[ERROR] meshcore_py not installed. pip install meshcore")
        return

    print("=" * 72)
    print("PART D: Live two-device ECB determinism test")
    print("=" * 72)
    print(f"Sender:  {sender_port}")
    print(f"Monitor: {monitor_port}")
    print()

    captured_payloads = []

    def on_rf_packet(event):
        # Capture RX_LOG_DATA events
        data = event if isinstance(event, dict) else event.__dict__
        payload_hex = data.get("payload", "")
        payload_type = data.get("payload_type", None)
        snr = data.get("snr", "?")
        rssi = data.get("rssi", "?")
        print(f"  [CAPTURED] type={payload_type} snr={snr} rssi={rssi} "
              f"len={len(payload_hex)//2} payload={payload_hex[:80]}...")
        captured_payloads.append(payload_hex)

    # Connect
    print("[*] Connecting to monitor...")
    monitor = await MeshCore.create_serial(monitor_port, 115200)
    sub = monitor.subscribe(EventType.RX_LOG_DATA, on_rf_packet)

    print("[*] Connecting to sender...")
    sender = await MeshCore.create_serial(sender_port, 115200)

    # Use a fixed timestamp so both messages have identical plaintext
    fixed_ts = int(time.time())
    test_msg = "ECB-TEST: identical message"

    print(f"[*] Sending message 1 (ts={fixed_ts}): '{test_msg}'")
    await sender.send_chan_msg(0, test_msg, fixed_ts)

    # Wait for propagation
    await asyncio.sleep(3)

    print(f"[*] Sending message 2 (ts={fixed_ts}): '{test_msg}'")
    await sender.send_chan_msg(0, test_msg, fixed_ts)

    await asyncio.sleep(3)

    # Analyze
    print()
    print("-" * 72)
    print(f"Captured {len(captured_payloads)} RF packets")
    if len(captured_payloads) >= 2:
        # Find matching payloads (same payload_type = group text)
        for i in range(len(captured_payloads)):
            for j in range(i + 1, len(captured_payloads)):
                if captured_payloads[i] == captured_payloads[j]:
                    print(f"[!!!] Packet {i} and {j} are BYTE-FOR-BYTE IDENTICAL:")
                    print(f"      {captured_payloads[i][:80]}...")
                    print()
                    print("[!] CONFIRMED: AES-ECB produces identical ciphertext for")
                    print("    identical plaintext. An SDR attacker can detect message")
                    print("    repetition without any knowledge of the encryption key.")
                    break
        else:
            # Check if encrypted portions match (skip header bytes)
            # Channel packets: [header] [chan_hash(1)] [MAC(2)] [ciphertext...]
            # The flood header + chan_hash may vary; compare from MAC onward
            print("[*] No exact full-payload match (routing headers may differ).")
            print("[*] Comparing encrypted portion (after channel hash byte):")
            for i in range(len(captured_payloads)):
                for j in range(i + 1, len(captured_payloads)):
                    p1 = captured_payloads[i]
                    p2 = captured_payloads[j]
                    # Skip first few bytes (header + route info varies)
                    # The encrypted part starts after the channel hash
                    # In hex: skip varying prefix, compare tail
                    min_len = min(len(p1), len(p2))
                    if min_len > 20:
                        # Compare last N bytes (the ciphertext body)
                        tail_len = min_len - 10  # skip first 5 bytes of hex
                        t1 = p1[-tail_len:]
                        t2 = p2[-tail_len:]
                        if t1 == t2:
                            print(f"  [!!!] Packets {i},{j}: encrypted body IDENTICAL")
                            print(f"        {t1[:60]}...")
    else:
        print("[*] Not enough packets captured. Ensure devices are on the same")
        print("    channel and within radio range.")

    # Cleanup
    sub.unsubscribe()
    await sender.disconnect()
    await monitor.disconnect()


# ========================================================================
# PART E: Replay attack demonstration (ties to Bug #16)
# ========================================================================
PART_E_NOTE = """
PART E: Replay Attack (conceptual -- ties to Bug #16)
======================================================
Because ECB mode produces the same ciphertext for the same plaintext,
and there is no nonce or sequence number in the MAC (Bug #16), an
attacker can:

  1. Capture a valid encrypted packet over-the-air with an SDR
  2. Retransmit the exact same bytes at any later time
  3. The receiver will accept it as a valid new message

The `hasSeen()` dedup table (SimpleMeshTables) uses a fixed-size ring
buffer of 128 entries. After ~128 new packets have been seen, the
original entry is evicted. An attacker merely waits for enough traffic
to cycle the table, then replays the captured packet.

With ECB, the attacker does not even need to understand the packet
structure -- a byte-for-byte copy is sufficient. With a proper
IV/nonce (the fix for Bug #5), each encryption would produce unique
ciphertext, and replayed packets could be detected if receivers track
seen nonces.
"""


# ========================================================================
# PART F: Random-padding mitigation demonstration
# ========================================================================
def part_f():
    print("=" * 72)
    print("PART F: Random-padding mitigation (non-breaking patch)")
    print("=" * 72)
    if not HAS_CRYPTO:
        print("[SKIP] pycryptodome not installed")
        return

    shared_secret = bytes.fromhex(
        "0123456789abcdef0123456789abcdef"
        "fedcba9876543210fedcba9876543210"
    )
    key = shared_secret[:CIPHER_KEY_SIZE]

    # --- Short message (fits in 1 block with padding) ---
    # [timestamp(4)] [type(1)] ["Hi\0"] = 8 bytes -> 1 block
    timestamp = struct.pack("<I", 1700000000)
    short_msg = timestamp + b"\x00" + b"Hi\x00"  # 8 bytes

    print(f"Short message ({len(short_msg)} bytes, 1 ECB block):")
    print(f"  Plaintext: {short_msg.hex()}")
    print()

    # Original (zero-padded): deterministic
    ct_zero_1 = meshcore_ecb_encrypt(key, short_msg, random_pad=False)
    ct_zero_2 = meshcore_ecb_encrypt(key, short_msg, random_pad=False)
    print(f"  Zero-padded (original):")
    print(f"    Encrypt 1: {ct_zero_1.hex()}")
    print(f"    Encrypt 2: {ct_zero_2.hex()}")
    print(f"    Identical?  {ct_zero_1 == ct_zero_2}  <-- VULNERABLE")
    print()

    # Patched (random-padded): non-deterministic
    ct_rand_1 = meshcore_ecb_encrypt(key, short_msg, random_pad=True)
    ct_rand_2 = meshcore_ecb_encrypt(key, short_msg, random_pad=True)
    print(f"  Random-padded (patched):")
    print(f"    Encrypt 1: {ct_rand_1.hex()}")
    print(f"    Encrypt 2: {ct_rand_2.hex()}")
    print(f"    Identical?  {ct_rand_1 == ct_rand_2}  <-- MITIGATED")
    print()

    # Verify decryption: both decrypt to same plaintext
    cipher = AES_LIB.new(key, AES_LIB.MODE_ECB)
    dec_1 = cipher.decrypt(ct_rand_1)
    dec_2 = cipher.decrypt(ct_rand_2)
    print(f"    Decrypt 1: {dec_1.hex()}  (first {len(short_msg)} bytes = plaintext)")
    print(f"    Decrypt 2: {dec_2.hex()}  (padding differs, but text is same)")
    print(f"    Plaintext match: {dec_1[:len(short_msg)] == dec_2[:len(short_msg)]}")
    print()

    # --- Long message (multiple blocks) ---
    long_msg = timestamp + b"\x00" + b"Alice: hello world, how are you doing?\x00"  # 44 bytes -> 3 blocks
    print(f"Long message ({len(long_msg)} bytes, {(len(long_msg) + 15) // 16} ECB blocks):")
    print()

    ct_long_1 = meshcore_ecb_encrypt(key, long_msg, random_pad=True)
    ct_long_2 = meshcore_ecb_encrypt(key, long_msg, random_pad=True)

    blk1 = [ct_long_1[i:i+16] for i in range(0, len(ct_long_1), 16)]
    blk2 = [ct_long_2[i:i+16] for i in range(0, len(ct_long_2), 16)]

    for i in range(len(blk1)):
        match = "SAME (still deterministic)" if blk1[i] == blk2[i] else "DIFFERENT (randomized padding)"
        is_last = " (last block)" if i == len(blk1) - 1 else ""
        print(f"  Block {i}{is_last}: {match}")

    print()
    print("[*] Summary:")
    print("    - Short messages (< 16 bytes): FULLY mitigated")
    print("      (entire ciphertext is non-deterministic)")
    print("    - Long messages: only last block mitigated")
    print("      (full aligned blocks remain deterministic under ECB)")
    print("    - A complete fix requires AES-CTR with per-packet nonce")
    print("      (protocol v2 -- breaking change)")
    print()


# ========================================================================
# Main
# ========================================================================
if __name__ == "__main__":
    import sys

    if "--live" in sys.argv:
        idx = sys.argv.index("--live")
        if len(sys.argv) < idx + 3:
            print("Usage: python bug5-aes-ecb.py --live SENDER_PORT MONITOR_PORT")
            print("Example: python bug5-aes-ecb.py --live COM3 COM4")
            sys.exit(1)
        sender_port = sys.argv[idx + 1]
        monitor_port = sys.argv[idx + 2]
        asyncio.run(run_live_poc(sender_port, monitor_port))
    else:
        print("Bug #5 PoC -- AES-128 ECB Mode Leaks Plaintext Patterns")
        print("========================================================")
        print()
        part_a()
        part_b()
        part_c()
        print(PART_E_NOTE)
        part_f()
        print()
        print("To run the live two-device test:")
        print("  python bug5-aes-ecb.py --live COM3 COM4")
