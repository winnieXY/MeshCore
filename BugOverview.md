# MeshCore Security & Bug Audit

**Audit Date:** April 2026  
**Scope:** `MeshCore/src/` — core mesh networking, packet handling, crypto, CLI, radio wrappers, serial interface, bridges  
**Focus:** Security vulnerabilities, programming bugs, and issues that can cause device hang / unresponsiveness

---

## Summary Table

| # | Severity | Fix Size | Category | File(s) | Short Description | Worst-Case Outcome |
|---|----------|----------|----------|---------|-------------------|--------------------|
| 1 | **CRITICAL** | **S** | Out-of-bounds write | `BaseChatMesh.cpp` | `data[len] = 0` writes 1 byte past the `payload[]` array on max-length messages | **Crash/reboot** on any node receiving a max-length DM or channel message. |
| 4 | **HIGH** | **S** | Pool exhaustion → hang | `Dispatcher.cpp` | Packet pool is finite and not recoverable; exhaustion makes device permanently deaf | **Permanent deaf node** — all roles. Rapid burst fills pool; node drops all inbound radio. |
| 5 | **HIGH** | **S** (partial) / **XL** (full) | AES-ECB mode | `Utils.cpp` | Encryption uses AES-128 in ECB mode with no IV/nonce — leaks plaintext patterns | **Passive traffic analysis + replay injection** on all encrypted messages. Partial mitigation (random padding, 2-line change, non-breaking) included. Full fix (AES-CTR) requires protocol version bump. |
| 6 | **HIGH** | **S** | TRACE flood DoS | `Mesh.cpp` | Crafted TRACE packets can drain TX budget and packet pool of target nodes | **Sustained DoS** on repeaters/room servers. Unauthenticated. Self-recovers when flood stops. |
| 7 | **HIGH** | **S** | Buffer overflow in CLI | `CommonCLI.cpp` | Unbounded `sprintf` into fixed `reply` buffer with attacker-controlled strings | **Crash/reboot or possible code execution** via long CLI command over BLE/radio/serial. |
| 8 | **MEDIUM** | **M** | ISR race condition | `RadioLibWrappers.cpp` | Global `volatile state` modified from ISR and main loop without atomic guards | **Single lost radio packet** (self-recovering). Practically untriggerable (~20μs window vs ≥10ms demod). |
| 9 | **HIGH** | **S** | Radio stuck — no recovery | `Dispatcher.cpp` | Radio-not-in-RX detection sets a flag but takes no corrective action | **Permanent deaf node** — all roles. 8s timeout fires but takes zero recovery action. |
| 10 | **MEDIUM** | **S** | `AdvertDataParser` OOB read | `AdvertDataHelpers.cpp` | Parser reads fields before checking if `app_data_len` is large enough | **Crash/reboot** on malformed advertisement from rogue enrolled node. |
| 11 | **MEDIUM** | **S** | TRACE path offset overflow | `Mesh.cpp` | `path_len << path_sz` can overflow `uint8_t`, causing OOB payload read | **Crash/reboot or wrong forwarding**. Unauthenticated — any SDR can trigger. |
| 12 | **LOW** | **S** | `PacketQueue` memory leak | `StaticPoolPacketManager.h` | `new[]` in constructor but no destructor to `delete[]` | **~11 KB leaked per recreation**. Low impact (objects created once in current firmware). |
| 13 | **LOW** | **S** | `restoreFrom` no validation | `SimpleMeshTables.h` | `_next_idx` read from file without bounds check — corrupted file causes OOB write | **Latent OOB write** — no callers invoke `restoreFrom()` today. |
| 14 | **MEDIUM** | **L** ⚠️ protocol | Group channel 1-byte hash | `BaseChatMesh.cpp`, `MeshCore.h`, `Mesh.cpp` | Channel lookup uses only 1 byte of SHA-256 — brute-force injection in ~109 min | **Garbage message injection** to any group channel. Unauthenticated. **Breaking change** — all nodes must update together. |
| 15 | **LOW** | **S** | `RNG::nextInt` modular bias + div-by-zero | `Utils.cpp` | `num % (_max - _min)` has bias; `_max == _min` causes division by zero | **Latent UB** — not remotely triggerable. All current callers safe. |
| 16 | **LOW** | **XL** ⚠️ protocol | No HMAC replay protection | `Utils.cpp` | No nonce/sequence in MAC; replayed packets accepted after hash table cycles | |
| 17 | **LOW** | **S** | `IdentityStore` sprintf overflow | `IdentityStore.cpp` | `sprintf` into 40-byte `filename` buffer with potentially long `_dir` + `name` | **Latent stack overflow** — not triggerable in current firmware. |
| 18 | **LOW** | **S** | Passwords in plaintext on flash + echoed in replies | `CommonCLI.cpp`, `BaseChatMesh.cpp` | Passwords echoed in encrypted CLI reply and stored unencrypted on flash | **Credential exposure** — physical flash access or authenticated admin CLI. |
| 19 | **LOW** | **M** | `ftoa` static buffer not reentrant | `TxtDataHelpers.cpp` | `static char` return buffer overwritten on second call in same expression | **Latent wrong CLI response** — not triggerable in current firmware. |
| 20 | **LOW** | **S** | Serial frame truncation | `ArduinoSerialInterface.cpp` | Oversized frames partially captured and returned as valid truncated data | **Silent data loss** on long serial messages. No crash, no security impact. |
| 22 | **CRITICAL** | **L** | Flash write blocks radio during `acl.save()` | `ClientACL.cpp`, `MyMesh.cpp` | Synchronous flash erase+write in main loop starves radio; triggers on every login | **Permanent radio hang (reboot required)** on nRF52. Chains into Bug #9. |

### Fix Size Legend

| Size | Meaning | Typical scope |
|------|---------|---------------|
| **S** | Small — trivial, low-risk | 1-2 files, <15 lines changed, no API/protocol change |
| **M** | Medium — moderate refactor | 1-3 files, 15-50 lines, possibly touches multiple call sites |
| **L** | Large — significant change | 4+ files or 50+ lines, may need careful testing across platforms |
| **XL** | Extra-large — protocol change | Requires coordinated rollout of all mesh nodes; breaking wire format |
| ⚠️ protocol | Breaking protocol change | All nodes in a mesh must update simultaneously or lose interop |

### Recommended Implementation Order

**Tier 1 — Do first (high severity, small fix, immediate payoff):**
| # | Severity | Fix Size | Why |
|---|----------|----------|-----|
| 1 | CRITICAL | S | 1-line bounds check prevents crash on every max-length message |
| 7 | HIGH | S | `sprintf` → `snprintf` in 2 files; prevents remote code execution |
| 9 | HIGH | S | ~15 lines in Dispatcher; prevents permanent deaf node |
| 10 | MEDIUM | S | 3-line bounds check; prevents unauthenticated crash |
| 11 | MEDIUM | S | 5-line type fix; prevents unauthenticated crash |

**Tier 2 — Do next (high severity, slightly more work):**
| # | Severity | Fix Size | Why |
|---|----------|----------|-----|
| 4 | HIGH | S | Pool eviction logic in Dispatcher; prevents permanent hang |
| 6 | HIGH | S | Rate limiter in Mesh.cpp; prevents unauthenticated DoS |
| 5 | HIGH | S (partial) | 2-line random padding; non-breaking partial crypto improvement |
| 22 | CRITICAL | L | Flash/radio coordination; requires nRF52-specific testing (7 files) |

**Tier 3 — Plan for (lower severity or bigger change):**
| # | Severity | Fix Size | Why |
|---|----------|----------|-----|
| 8 | MEDIUM | M | ISR critical sections; correct but practically untriggerable race |
| 19 | LOW | M | API change for ftoa; 9 call sites to update; latent-only |
| 15 | LOW | S | Div-by-zero guard; latent-only, all current callers safe |
| 17 | LOW | S | sprintf → snprintf; latent-only |
| 18 | LOW | S | Stop echoing password; low-impact credential hardening |
| 13 | LOW | S | Clamp index after restore; latent-only, no current callers |
| 12 | LOW | S | Add destructors; affects unit tests mainly |
| 20 | LOW | S | Reject oversized frame; data-loss-only, no security impact |

**Tier 4 — Long-term / breaking protocol changes:**
| # | Severity | Fix Size | Why |
|---|----------|----------|-----|
| 14 | MEDIUM | L ⚠️ | Channel hash 1→4 bytes; **all nodes must update together** |
| 16 | LOW | XL ⚠️ | Add replay nonce to HMAC; **wire format change** |
| 5 | HIGH | XL (full) | AES-CTR with per-packet nonce; **protocol version bump** |

---

## Detailed Findings

---

### Bug #1 — CRITICAL: Out-of-Bounds Write on Text Message Receive

**File:** `src/helpers/BaseChatMesh.cpp` (lines ~215 and ~372)  
**Impact:** Memory corruption, device crash/hang on receiving a max-length text or group text message.

**Worst-Case Outcome:** Any node (repeater, room server, sensor, or companion) that receives a max-length DM or channel message crashes immediately. The `data[len]=0` write corrupts the stack frame of `onRecvPacket()`. On nRF52 (ARM Cortex-M4) this overwrites saved registers or the return address → HardFault → reboot. On ESP32 it may corrupt adjacent stack variables → undefined behavior or `LoadProhibited` exception → reboot. Triggerable by any peer who shares a channel secret (channel messages) or any contact (DMs). No brute-force needed for normal API traffic — just send the longest possible message.

**Description:**  
When a text message or group text message is received, the code writes a null terminator at `data[len]` to turn the decrypted payload into a C string. The `data` pointer points into a `uint8_t data[MAX_PACKET_PAYLOAD]` local array (184 bytes). If `len == MAX_PACKET_PAYLOAD` (which is the case when the encrypted payload fills the entire packet), this writes one byte past the end of the array, corrupting the stack. On embedded devices this can overwrite a return address or adjacent local variable, leading to an immediate crash or unpredictable behavior.

The same pattern is repeated in multiple firmware examples (`simple_repeater`, `simple_room_server`, `simple_sensor`).

**Code (peer text message):**
```cpp
// BaseChatMesh.cpp:215 — onPeerDataRecv()
if (type == PAYLOAD_TYPE_TXT_MSG && len > 5) {
    uint32_t timestamp;
    memcpy(&timestamp, data, 4);
    uint8_t flags = data[4] >> 2;

    // len can be > original length, but 'text' will be padded with zeroes
    data[len] = 0; // ← BUG: writes past end of data[] when len == MAX_PACKET_PAYLOAD
```

**Code (group text message):**
```cpp
// BaseChatMesh.cpp:372 — onGroupDataRecv()
    uint32_t timestamp;
    memcpy(&timestamp, data, 4);

    // len can be > original length, but 'text' will be padded with zeroes
    data[len] = 0; // ← BUG: same out-of-bounds write
```

**Note:** `data` is declared on the stack in `Mesh::onRecvPacket()` as:
```cpp
uint8_t data[MAX_PACKET_PAYLOAD]; // 184 bytes
int len = Utils::MACThenDecrypt(secret, data, macAndData, pkt->payload_len - i);
// len can be up to MAX_PACKET_PAYLOAD (184)
```

---

### Bug #4 — HIGH: Packet Pool Exhaustion Causes Permanent Unresponsiveness

**File:** `src/helpers/StaticPoolPacketManager.cpp`, `src/Dispatcher.cpp`  
**Impact:** Node becomes permanently deaf to all traffic; requires reboot to recover.

**Worst-Case Outcome:** Permanent deafness on any role. On `companion_radio` (16-slot pool): a BLE-paired phone app sending a burst of ~20 messages fills the pool before the radio can drain it. On repeater/room_server (32-slot pool): a TRACE/flood storm or a fast series of client logins can exhaust the pool. Once exhausted, `allocNew()` returns NULL for every incoming radio packet — the node is silently deaf to all mesh traffic. Only a reboot recovers. No external attacker needed — a legitimate client with poor connectivity retrying rapidly can trigger this.

**Description:**  
The packet pool is a fixed-size static allocation. Once all packets are in use (held in outbound queue, inbound queue, or via `ACTION_MANUAL_HOLD`), `allocNew()` returns `NULL` and all incoming radio packets are silently discarded. There is no mechanism to reclaim or forcibly free queued packets. A burst of flood or TRACE packets, combined with long retransmit delays, can fill the pool. Once full, the node cannot receive or process any new traffic until rebooted.

The `ACTION_MANUAL_HOLD` path is particularly dangerous — if a sub-class holds a packet and never releases it (e.g. due to a logic error), that packet slot is permanently lost.

**Code:**
```cpp
// StaticPoolPacketManager.cpp
mesh::Packet* StaticPoolPacketManager::allocNew() {
  return unused.removeByIdx(0);  // just get first one (returns NULL if empty)
}

// Dispatcher.cpp — checkRecv()
pkt = _mgr->allocNew();
if (pkt == NULL) {
    MESH_DEBUG_PRINTLN("WARNING: received data, no unused packets available!");
    // ← pkt stays NULL, incoming radio data is simply dropped!
}

// Dispatcher.cpp — processRecvPacket()
void Dispatcher::processRecvPacket(Packet* pkt) {
  DispatcherAction action = onRecvPacket(pkt);
  if (action == ACTION_RELEASE) {
    _mgr->free(pkt);
  } else if (action == ACTION_MANUAL_HOLD) {
    // sub-class is wanting to manually hold Packet instance
    // ← if sub-class never calls releasePacket(), this slot is LEAKED forever
  } else {
    _mgr->queueOutbound(pkt, priority, futureMillis(_delay));
  }
}
```

---

### Bug #5 — HIGH: AES-128 ECB Mode Leaks Plaintext Patterns

**File:** `src/Utils.cpp`  
**Impact:** Identical plaintext blocks produce identical ciphertext; enables pattern analysis and replay detection.

**Worst-Case Outcome:** Passive traffic analysis and replay injection on **all encrypted messages** (DMs, channel messages, CLI commands). Any LoRa SDR within radio range can capture packets and determine, **without the key**, that two messages are identical — because AES-ECB is deterministic. Group channel messages are especially exposed: all members share the same channel secret, so a common greeting from the same sender at the same timestamp produces byte-for-byte identical ciphertext. Attacker can also build a first-block codebook exploiting the known plaintext structure (`[timestamp(4)] [type(1)] [sender_name...]`) — identical first 16 bytes produce identical first ciphertext block, leaking sender identity and timing. Combined with Bug #16 (no replay protection), captured ciphertext packets can be retransmitted verbatim after the `hasSeen()` ring buffer cycles (~128 packets), and receivers will accept them as new valid messages. Does NOT enable direct decryption of unknown messages, but degrades encryption from IND-CPA (indistinguishable under chosen-plaintext) to a deterministic permutation — a fundamental cryptographic weakness. **Partial mitigation available (non-breaking):** replacing zero-padding with random-padding in the last ECB block (`memset(tmp,0,16)` -> `random(tmp,16)` in `encrypt()`) makes short messages (< 16 bytes plaintext, i.e. single-block) fully non-deterministic and randomizes the last block of all longer messages. This is backward-compatible — decryption ignores padding bytes. Full aligned blocks remain deterministic under ECB; a complete fix (AES-CTR with per-packet nonce) requires a future protocol version bump.

**PoC:** `bug5-aes-ecb.py`  
**Patch:** `bug5-aes-ecb.patch`

**Description:**  
All encryption uses AES-128 in ECB (Electronic Codebook) mode — each 16-byte block is encrypted independently with no chaining, no IV, and no nonce. This is a well-known insecure mode:
- Identical plaintext blocks produce identical ciphertext blocks, leaking structural information.
- The same message encrypted with the same key always produces the same ciphertext, enabling an observer to detect repeated messages.
- Padding uses zero bytes, further reducing entropy in the last block.

**Code:**
```cpp
// Utils.cpp — encrypt()
int Utils::encrypt(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len) {
  AES128 aes;
  uint8_t* dp = dest;

  aes.setKey(shared_secret, CIPHER_KEY_SIZE);
  while (src_len >= 16) {
    aes.encryptBlock(dp, src);     // <- ECB mode: each block encrypted independently
    dp += 16; src += 16; src_len -= 16;
  }
  if (src_len > 0) {  // remaining partial block
    uint8_t tmp[16];
    memset(tmp, 0, 16);            // <- zero-padding
    memcpy(tmp, src, src_len);
    aes.encryptBlock(dp, tmp);     // <- no IV, no chaining
    dp += 16;
  }
  return dp - dest;
}
```

**Severity Review:** Keeping **HIGH**. ECB mode is a fundamental cryptographic weakness that affects every encrypted packet in the protocol. It does not directly expose plaintext (the AES key is still required), but it violates the basic expectation of semantic security (IND-CPA). The practical exploitation path — passive SDR traffic analysis + codebook construction + replay — is realistic for a motivated attacker near the mesh. However, it requires radio proximity and does not yield plaintext directly, which is why it stays HIGH rather than CRITICAL.

---

### Bug #6 — HIGH: Denial-of-Service via TRACE Packet Flood

**File:** `src/Mesh.cpp`  
**Impact:** Remote attacker can drain TX budget and fill packet queue of any target node.

**Worst-Case Outcome:** Sustained denial-of-service on **repeaters** and **room servers** (any firmware with `allowPacketForward()` returning true). **Unauthenticated** — TRACE packets carry no signature or encryption, so any LoRa radio (cheap module, SDR, or modified firmware) within radio range can execute this attack. The attacker sends a continuous stream of TRACEs, each with a unique `trace_tag` (bypassing the 128-entry `hasSeen()` dedup table) and the target's 1-byte path hash (only 256 possibilities, trivially guessable or known from public key). Each matching TRACE is queued for retransmit, consuming 1 of 32 pool slots and burning TX airtime budget. At ~10 TRACEs/sec, the pool is exhausted in ~3 seconds; the TX budget drops to 0, pushing `next_tx_time` indefinitely into the future. Result: the repeater becomes **deaf** (pool full → can't allocate for RX) and **mute** (no TX budget → can't send). Normal mesh traffic is completely blocked for the duration of the flood. **This is NOT a permanent hang** — once the attacker stops transmitting, queued TRACEs drain via TX or `outbound_expiry` timeout (seconds), the pool refills, and `updateTxBudget()` restores the TX budget proportionally to elapsed idle time. The node self-recovers without reboot. The damage is availability-during-attack only, unlike Bugs #22/#9/#4 which cause permanent hangs. Multi-hop TRACE paths amplify through intermediate repeaters, allowing a single attacker to disrupt an entire chain. Companion radio nodes are unaffected (`allowPacketForward()` returns false).

**Description:**  
TRACE packets use direct routing and bypass the flood deduplication. The TRACE handler forwards the packet if the current node's hash matches a byte in the payload path — and since `PATH_HASH_SIZE` is 1 byte, this is easy to target. The forwarding allocates a priority-5 outbound slot and consumes TX airtime budget. An attacker can generate a continuous stream of unique TRACE packets (each with a different `trace_tag`), all targeting a specific node's 1-byte hash, to:
1. Fill the outbound packet queue
2. Drain the TX duty-cycle budget
3. Exhaust the packet pool

**Code:**
```cpp
// Mesh.cpp — onRecvPacket(), TRACE handler
if (pkt->isRouteDirect() && pkt->getPayloadType() == PAYLOAD_TYPE_TRACE) {
    if (pkt->path_len < MAX_PATH_SIZE) {
      // ...
      uint8_t flags = pkt->payload[i++];
      uint8_t path_sz = flags & 0x03;

      uint8_t len = pkt->payload_len - i;
      uint8_t offset = pkt->path_len << path_sz;
      if (offset >= len) {
        onTraceRecv(pkt, trace_tag, auth_code, flags, pkt->path, &pkt->payload[i], len);
      } else if (self_id.isHashMatch(&pkt->payload[i + offset], 1 << path_sz)
                 && allowPacketForward(pkt) && !_tables->hasSeen(pkt)) {
        pkt->path[pkt->path_len++] = (int8_t) (pkt->getSNR()*4);
        uint32_t d = getDirectRetransmitDelay(pkt);
        return ACTION_RETRANSMIT_DELAYED(5, d); // ← queued for retransmit, consuming pool + TX budget
      }
    }
    return ACTION_RELEASE;
}
```

---

### Bug #7 — HIGH: Unbounded `sprintf` Buffer Overflow in CLI Handler

**File:** `src/helpers/CommonCLI.cpp`  
**Impact:** Stack buffer overflow if an attacker sends a long CLI command; can corrupt memory or crash the device.

**Worst-Case Outcome:** Crash/reboot or potential code execution on repeater, room server, or sensor nodes. **Remote attack (BLE/radio):** An admin-authenticated client sends a 179-byte CLI command like `set AAAA...` (175-byte config). The firmware writes `"unknown config: "` (16 bytes) + 175 bytes = 191 bytes into a 161-byte `reply[]` buffer → **30-byte stack overflow**. On ARM Cortex-M4 (nRF52) this overwrites saved r4-r7 and the return address (LR) → HardFault or attacker-controlled PC. **Serial attack:** 155-byte config → 171 bytes into 160-byte buffer → 11-byte overflow. The `get owner.info` path writes up to 122 bytes char-by-char with zero bounds checking. All three firmware variants (repeater, room server, sensor) are affected.

**Description:**  
Multiple `handleCommand` / `handleSetCmd` code paths write attacker-controlled string data into the `reply` buffer using `sprintf` without any length check. The `reply` buffer is typically a fixed-size stack array in the calling firmware (often 160–256 bytes). A crafted long command string can overflow this buffer.

**Code (unknown config echo):**
```cpp
// CommonCLI.cpp:729 — handleSetCmd()
  } else {
    sprintf(reply, "unknown config: %s", config);
    // ← 'config' is attacker-controlled, no length limit
  }
```

**Code (password echo):**
```cpp
// CommonCLI.cpp:288 — handleCommand()
    } else if (memcmp(command, "password ", 9) == 0) {
      StrHelper::strncpy(_prefs->password, &command[9], sizeof(_prefs->password));
      savePrefs();
      sprintf(reply, "password now: %s", _prefs->password);
```

**Code (owner.info — char-by-char write without bounds):**
```cpp
// CommonCLI.cpp:787 — handleGetCmd()
  } else if (memcmp(config, "owner.info", 10) == 0) {
    *reply++ = '>';
    *reply++ = ' ';
    const char* sp = _prefs->owner_info;
    while (*sp) {
      *reply++ = (*sp == '\n') ? '|' : *sp;  // ← no check on reply buffer end
      sp++;
    }
    *reply = 0;
  }
```

---

### Bug #8 — MEDIUM: Race Condition on Global Radio State Variable

**File:** `src/helpers/radiolib/RadioLibWrappers.cpp`  
**Impact:** Missed packets or radio state desync on interrupt timing edge cases.

**Worst-Case Outcome:** Single lost radio packet (self-recovering). In `recvRaw()`, the ISR can set `STATE_INT_READY` in the ~20μs window between `state = STATE_IDLE` and `state = STATE_RX`; the latter clobbers the flag, losing one received packet. The race window is orders of magnitude smaller than LoRa demodulation time (≥10ms at SF7), making occurrence probability vanishingly low. Not externally triggerable. System self-recovers on the next incoming packet.

**PoC:** No PoC can be written. The race window (~20μs between two assignments in `recvRaw()`) is 500× shorter than the fastest LoRa packet demodulation time (~10ms at SF7). There is no meshcore_py API or external radio stimulus that can control ARM hardware interrupt timing at the instruction level. The bug is proven by code analysis only.

**Severity Review:** MEDIUM — kept. The race is real but the window is effectively impossible to hit: LoRa demodulation takes ≥10ms, the vulnerable window is ~20μs, and the consequence (one lost packet) is indistinguishable from normal RF packet loss. No permanent state corruption, no hang, no security impact. Self-recovers on next packet. The fix is a defensive-correctness improvement, not an urgent operational fix.

**Description:**  
The global `volatile uint8_t state` variable is written from the ISR (`setFlag()` — called on packet received or TX complete interrupt) and read/written from the main loop (`recvRaw()`, `isSendComplete()`, `startSendRaw()`). While `volatile` prevents compiler optimization, it does not provide atomicity on the read-check-write patterns in the main loop. On ARM Cortex-M (ESP32, nRF52), an interrupt can fire between a read and a write, causing TOCTOU races.

**Race analysis — all `state` writers in the main loop:**

| Function | Pattern | Race window | Practical risk |
|----------|---------|-------------|----------------|
| `recvRaw()` | `state = STATE_IDLE` then `state = STATE_RX` | ~20μs (includes `startReceive()` SPI call) | **Primary risk.** ISR sets `INT_READY` between the two assignments; `state = STATE_RX` clobbers it. One RX packet lost. |
| `isSendComplete()` | Check `INT_READY`, then `state = STATE_IDLE` | <1μs | **No practical risk.** During TX, only the TX-complete ISR fires; no second ISR can occur in this window. |
| `startSendRaw()` | `state = STATE_TX_WAIT` | <1μs | **No practical risk.** Radio is being switched from IDLE to TX; no ISR pending. |
| `onSendFinished()` | `state = STATE_IDLE` | <1μs | **No practical risk.** Called immediately after `isSendComplete()` returns true; no new ISR expected. |
| `idle()` / `resetAGC()` / `startRecv()` | `state = STATE_IDLE` or `STATE_RX` | <1μs | **Minimal risk.** Called during initialization or calibration, not in hot receive path. |

**The primary race in `recvRaw()` step-by-step:**
```
Main loop:
  [A] if (state & STATE_INT_READY)    → true (RX complete ISR fired)
  [B] readData() from radio FIFO      (SPI: ~50-200μs)
  [C] state = STATE_IDLE              → clears INT_READY + base state
  ------- ISR fires here: state |= STATE_INT_READY → state = 0x10 -------
  [D] if (state != STATE_RX)          → true (0x10 != 0x01)
  [E] startReceive()                  (SPI: ~10-50μs, puts radio in RX)
  [F] state = STATE_RX                → state = 0x01, CLOBBERS STATE_INT_READY
      → Packet that caused the ISR between [C] and [F] is LOST
```

**Why it's practically untriggerable:** For the ISR to fire between [C] and [F], a second packet must have completed full LoRa demodulation in that window. Even at the fastest setting (SF7/500kHz), a minimum-size packet takes ~5ms to demodulate. The [C]-to-[F] window is ~20μs. The radio's continuous-RX mode can overlap demodulation of a new packet with main-loop processing, but the new packet's ISR won't fire until demodulation completes — which takes far longer than the race window.

**Code (current — vulnerable):**
```cpp
static volatile uint8_t state = STATE_IDLE;

static void setFlag(void) {
  state |= STATE_INT_READY;  // ISR: read-modify-write (safe — ISR can't be preempted by main loop)
}

int RadioLibWrapper::recvRaw(uint8_t* bytes, int sz) {
  int len = 0;
  if (state & STATE_INT_READY) {         // check flag
    len = _radio->getPacketLength();
    // ... read data ...
    state = STATE_IDLE;                  // [C] clear flag — ISR can fire after this
  }
  if (state != STATE_RX) {
    int err = _radio->startReceive();
    if (err == RADIOLIB_ERR_NONE) {
      state = STATE_RX;                  // [F] CLOBBERS any INT_READY set since [C]
    }
  }
  return len;
}
```

**Fix:** See `bug8-isr-race.patch` — wraps all main-loop reads and writes of `state` in `noInterrupts()` / `interrupts()` critical sections. Key changes:
1. `recvRaw()`: Atomically snapshot+clear `INT_READY` at the start; after `startReceive()`, only set `STATE_RX` if no new `INT_READY` arrived during the SPI call.
2. `isSendComplete()`: Atomically test-and-clear `INT_READY`.
3. All other writers (`idle()`, `startRecv()`, `resetAGC()`, `startSendRaw()`, `onSendFinished()`): Wrap `state` writes in critical sections for consistency.
4. All readers (`isInRecvMode()`, `loop()`): Snapshot `state` under `noInterrupts()` to prevent torn reads.

---

### Bug #9 — HIGH: Radio Stuck Detection With No Recovery

**File:** `src/Dispatcher.cpp`  
**Impact:** If the radio gets stuck in non-RX mode, the device becomes permanently deaf without reboot.

**Worst-Case Outcome:** Permanent deaf node requiring reboot — all roles (repeater, room server, sensor, companion). This bug is the **defense-in-depth failure** that makes Bug #22 fatal: when `acl.save()` corrupts the SPI bus on nRF52, the SX1262 radio gets stuck in a non-RX state. The 8-second timeout fires, sets `ERR_EVENT_STARTRX_TIMEOUT`, but takes **no recovery action** — no radio reset, no AGC cycle, no reboot. The radio stays stuck permanently. Even without Bug #22, any hardware glitch, power brownout, or SPI noise that leaves the radio in IDLE or TX state will be permanently fatal. The node appears online (BLE still works, serial still responds) but never receives a radio packet again.

**Description:**  
The dispatcher checks if the radio has been outside RX mode for more than 8 seconds and sets an error flag. However, this flag is never acted upon — no attempt is made to reset the radio, force it back into RX mode, or reboot. The flag is only cleared by a manual `resetStats()` call. If the radio genuinely gets stuck (e.g. after a failed TX or a hardware glitch), the device silently stops receiving packets forever.

**Code:**
```cpp
// Dispatcher.cpp — loop()
  bool is_recv = _radio->isInRecvMode();
  if (is_recv != prev_isrecv_mode) {
    prev_isrecv_mode = is_recv;
    if (!is_recv) {
      radio_nonrx_start = _ms->getMillis();
    }
  }
  if (!is_recv && _ms->getMillis() - radio_nonrx_start > 8000) {
    _err_flags |= ERR_EVENT_STARTRX_TIMEOUT;
    // ← That's it. No recovery action. Radio stays stuck.
  }
```

---

### Bug #10 — MEDIUM: `AdvertDataParser` Reads Past Buffer

**File:** `src/helpers/AdvertDataHelpers.cpp`  
**Impact:** Out-of-bounds read on crafted short advertisement packets; may read adjacent stack/heap data.

**Worst-Case Outcome:** Crash/reboot on any node (all roles) that processes a malformed advertisement. A compromised or rogue enrolled node broadcasts an advert with `app_data_len=1` and `flags=0x70` (all field flags set). The parser immediately performs 4 `memcpy()` calls reading 12 bytes past the 1-byte buffer — into adjacent stack/heap memory. On ESP32 this may cross into flash-mapped IRAM → `LoadProhibited` exception → reboot. On nRF52 it may cross an MPU boundary → HardFault → reboot. The attack requires a valid ed25519 signature (attacker must own a key pair = be an enrolled node), but hits **every receiver in radio range** simultaneously. The read data doesn't leak back to the attacker (no info disclosure), but the crash is the goal.

**Description:**  
The `AdvertDataParser` constructor checks if flags indicate the presence of lat/lon (8 bytes) and feature fields (2 bytes each) and reads them from `app_data` using `memcpy`. The bounds check (`app_data_len >= i`) only happens *after* all the reads. A crafted short payload with flags claiming lat/lon and features but providing only a few bytes will cause `memcpy` to read past the end of the `app_data` buffer.

**Code:**
```cpp
// AdvertDataHelpers.cpp — AdvertDataParser constructor
  AdvertDataParser::AdvertDataParser(const uint8_t app_data[], uint8_t app_data_len) {
    _flags = app_data[0];
    _valid = false;

    int i = 1;
    if (_flags & ADV_LATLON_MASK) {
      memcpy(&_lat, &app_data[i], 4); i += 4;  // ← reads 4 bytes, no check on app_data_len
      memcpy(&_lon, &app_data[i], 4); i += 4;  // ← reads another 4 bytes
    }
    if (_flags & ADV_FEAT1_MASK) {
      memcpy(&_extra1, &app_data[i], 2); i += 2;  // ← no bounds check yet
    }
    if (_flags & ADV_FEAT2_MASK) {
      memcpy(&_extra2, &app_data[i], 2); i += 2;
    }

    if (app_data_len >= i) {  // ← bounds check happens HERE, too late!
      // ... parse name ...
      _valid = true;
    }
  }
```

---

### Bug #11 — MEDIUM: TRACE Path Offset Overflow Causes OOB Read

**File:** `src/Mesh.cpp`  
**Impact:** Out-of-bounds read in payload array from crafted TRACE packets; may crash or leak memory.

**Worst-Case Outcome:** Crash/reboot or unintended packet forwarding on any node (all roles). **Unauthenticated** — TRACE packets require no signature or encryption, so any SDR or modified firmware within radio range can trigger this. The attacker crafts a TRACE with `path_len=32` and `flags=0x03` (path_sz=3). The firmware computes `offset = 32 << 3 = 256`, which truncates to `uint8_t` 0. This causes the wrong branch (forward instead of "end of path"), and `isHashMatch()` reads 8 bytes from `payload[9]` — which may be past the actual payload end. On nRF52 → HardFault → reboot. On ESP32 → `LoadProhibited` → reboot. If the OOB bytes happen to match the node's pub_key prefix (1/256 chance for 1-byte hash), the node incorrectly forwards the TRACE, amplifying the attack. Continuous broadcast of malformed TRACEs = low-cost wide-area DoS against every node in radio range.

**Description:**  
In the TRACE packet handler, `offset` is calculated as `pkt->path_len << path_sz` where `path_sz` comes from attacker-controlled flags (bits 0–1, so 0–3). If `path_len` is, say, 60 and `path_sz` is 3, then `60 << 3 = 480`, which overflows the `uint8_t offset` variable (wraps to 480 & 0xFF = 224). The subsequent `pkt->payload[i + offset]` can then read past the 184-byte payload buffer.

**Code:**
```cpp
// Mesh.cpp — TRACE handler
      uint8_t flags = pkt->payload[i++];
      uint8_t path_sz = flags & 0x03;  // ← attacker-controlled: 0..3

      uint8_t len = pkt->payload_len - i;
      uint8_t offset = pkt->path_len << path_sz;  // ← overflow! e.g. 60 << 3 = 480 → truncated to 224
      if (offset >= len) {
        onTraceRecv(pkt, trace_tag, auth_code, flags, pkt->path, &pkt->payload[i], len);
      } else if (self_id.isHashMatch(&pkt->payload[i + offset], 1 << path_sz)
                 // ← i + offset can exceed payload_len
```

---

### Bug #12 — LOW: `PacketQueue` Has No Destructor (Memory Leak)

**File:** `src/helpers/StaticPoolPacketManager.h`  
**Impact:** If the packet manager is ever destroyed/recreated, all dynamically allocated queue memory leaks permanently.

**Worst-Case Outcome:** On current embedded firmware: **no direct impact** — `StaticPoolPacketManager` is created once at startup and never destroyed. However: (1) Unit tests or CI builds using ASAN/Valgrind will flag ~11 KB of leaked memory per `StaticPoolPacketManager(32)` destruction (3 queue arrays × 9×32 = 864 bytes + 32 Packet objects × ~258 bytes = ~9.1 KB), masking real bugs in leak reports. (2) The `PacketManager` base class (`Dispatcher.h`) lacks a `virtual` destructor, so `delete` via a `PacketManager*` pointer is **undefined behavior** in C++ — the derived destructor (if added) would never be called. (3) Any future runtime reconfiguration (changing pool size, hot-restart) would leak all pool memory on each cycle. All roles affected equally (repeater, room server, sensor, companion).

**Description:**  
`PacketQueue` allocates three arrays with `new[]` in its constructor but has no destructor to free them. While on embedded devices this is typically a one-time allocation, any reconfiguration or test scenario that recreates the manager will permanently leak memory.

**Code:**
```cpp
// StaticPoolPacketManager.cpp
PacketQueue::PacketQueue(int max_entries) {
  _table = new mesh::Packet*[max_entries];      // ← allocated
  _pri_table = new uint8_t[max_entries];         // ← allocated
  _schedule_table = new uint32_t[max_entries];   // ← allocated
  _size = max_entries;
  _num = 0;
}
// ← No destructor defined anywhere — no delete[]
```

---

### Bug #13 — LOW: `SimpleMeshTables::restoreFrom` Loads Indexes Without Validation

**File:** `src/helpers/SimpleMeshTables.h`  
**Impact:** Corrupted file causes out-of-bounds write on next `hasSeen()` call; memory corruption / crash.

**Worst-Case Outcome:** **Latent OOB write on ESP32** — currently no firmware variant calls `restoreFrom()`, so this bug cannot be triggered today. However, `restoreFrom()` is a public method compiled on ESP32 (behind `#ifdef ESP32`). If table persistence is added in the future, a corrupted flash file (from wear, power loss during write, or bit-flip) would load `_next_idx` > 128, and the next `hasSeen()` call writes 8 bytes at offset `_next_idx * 8` past the start of `_hashes[]` — up to ~7 KB beyond the array. This corrupts heap metadata or adjacent globals, causing an immediate crash or silent data corruption. Worse, because the corrupted file is read on every boot, this becomes a **crash loop** — the device reboots, loads the corrupt file, crashes, reboots — until the flash file is manually erased via serial or full reflash.

**Description:**  
`restoreFrom()` reads `_next_idx` and `_next_ack_idx` from a file without validating they are within bounds. If the file is corrupted (flash wear, incomplete write), `_next_idx` could be > `MAX_PACKET_HASHES`, causing `_hashes[_next_idx * MAX_HASH_SIZE]` to write outside the array on the next `hasSeen()` call.

**Code:**
```cpp
// SimpleMeshTables.h
  void restoreFrom(File f) {
    f.read(_hashes, sizeof(_hashes));
    f.read((uint8_t *) &_next_idx, sizeof(_next_idx));       // ← no bounds check!
    f.read((uint8_t *) &_acks[0], sizeof(_acks));
    f.read((uint8_t *) &_next_ack_idx, sizeof(_next_ack_idx)); // ← no bounds check!
  }

// Later in hasSeen():
    memcpy(&_hashes[_next_idx * MAX_HASH_SIZE], hash, MAX_HASH_SIZE);
    _next_idx = (_next_idx + 1) % MAX_PACKET_HASHES;
    // ← if _next_idx was 999, _hashes[999*8] writes WAY past array end
```

---

### Bug #14 — MEDIUM: Group Channel Hash Uses Only 1 Byte

**File:** `src/MeshCore.h`, `src/Mesh.h`, `src/Mesh.cpp`, `src/helpers/BaseChatMesh.cpp`  
**Impact:** High collision rate between channels; brute-force message injection feasible in ~109 minutes.

**Worst-Case Outcome:** **Garbage message injection to any group channel** — unauthenticated, any LoRa SDR or modified firmware in radio range. The group message packet format uses only 1 byte of SHA-256 for channel identification (`PATH_HASH_SIZE = 1` in `MeshCore.h`). With 256 possible hash values, a node with 40 channels has a 96% chance of at least one collision pair (birthday problem). An attacker who knows or guesses the target channel's hash byte (1/256 blind, or trivially enumerable) needs only brute-force the 2-byte HMAC (`CIPHER_MAC_SIZE = 2`, 65,536 possibilities). At ~10 LoRa packets/sec, near-certain MAC collision in ~109 minutes. The successfully "injected" message decrypts to random garbage (attacker lacks the AES key), but `MACThenDecrypt` returns success and `onGroupDataRecv` processes it — displaying a corrupted message from a random "sender" (first 5 bytes parsed as sender ID + timestamp). Secondary impact: **CPU waste DoS** — flooding all 256 hash byte values forces the target to attempt HMAC-SHA256 + AES-128 decryption for every locally matching channel per packet. With 40 channels, a 256-packet burst triggers 40 full crypto operations. This is a **protocol-level design weakness** — the fix requires increasing the channel hash size (breaking backward compatibility with older firmware).

**Description:**  
The `searchChannelsByHash` function compares only the first byte of the channel hash. With 256 possible values, roughly 1 in 256 channels will match any incoming group packet's hash byte. The only remaining authentication is the 2-byte HMAC, which can be brute-forced in ~65,536 attempts.

The root constant is `PATH_HASH_SIZE = 1` in `MeshCore.h`, which controls both `GroupChannel::hash[]` storage and the number of hash bytes written into group message packets. The hash is the first byte of SHA-256(channel_secret).

**Code (channel lookup — 1-byte comparison):**
```cpp
// BaseChatMesh.cpp
int BaseChatMesh::searchChannelsByHash(const uint8_t* hash, mesh::GroupChannel dest[], int max_matches) {
  int n = 0;
  for (int i = 0; i < MAX_GROUP_CHANNELS && n < max_matches; i++) {
    if (channels[i].channel.hash[0] == hash[0]) {  // ← only 1 byte compared!
      dest[n++] = channels[i].channel;
    }
  }
  return n;
}
```

**Code (receive path — 1-byte extraction):**
```cpp
// Mesh.cpp — onRecvPacket()
    case PAYLOAD_TYPE_GRP_DATA:
    case PAYLOAD_TYPE_GRP_TXT: {
      int i = 0;
      uint8_t channel_hash = pkt->payload[i++];  // ← only 1 byte read from packet
      uint8_t* macAndData = &pkt->payload[i];
      // ...
      int num = searchChannelsByHash(&channel_hash, channels, 4);
      for (int j = 0; j < num; j++) {
        int len = Utils::MACThenDecrypt(channels[j].secret, data, macAndData, pkt->payload_len - i);
        if (len > 0) {  // MAC matched — packet accepted, even if content is garbage
          onGroupDataRecv(pkt, pkt->getPayloadType(), channels[j], data, len);
          break;
        }
      }
    }
```

**Code (packet construction — 1-byte hash written):**
```cpp
// Mesh.cpp — createGroupDatagram()
  int len = 0;
  memcpy(&packet->payload[len], channel.hash, PATH_HASH_SIZE); len += PATH_HASH_SIZE;  // ← 1 byte
  len += Utils::encryptThenMAC(channel.secret, &packet->payload[len], data, data_len);
```

**Code (protocol constant):**
```cpp
// MeshCore.h
#define PATH_HASH_SIZE       1   // ← only 1 byte for all hash-based lookups
```
```

---

### Bug #15 — LOW: `RNG::nextInt` Has Modular Bias and Division-by-Zero Risk

**File:** `src/Utils.cpp`, `examples/companion_radio/MyMesh.cpp`  
**Impact:** Division by zero crash if `_max == _min`; biased random output for BLE PIN generation.

**Worst-Case Outcome:** **Latent undefined behavior** — not remotely triggerable in current firmware. All callers use hardcoded bounds where `_min < _max` (e.g., `nextInt(0, 5)`, `nextInt(1, 4)`, `nextInt(100000, 999999)`). The div-by-zero would only occur if a future caller passes dynamically computed bounds where equality is possible (e.g., `nextInt(0, num_peers)` when `num_peers == 0`). On ARM Cortex-M, unsigned integer modulo by zero is undefined behavior — GCC on ARM typically returns 0 silently, but some toolchains trap to HardFault → device reboot. The modular bias affects BLE PIN generation (`nextInt(100000, 999999)`, range = 899,999): 19.1% of PINs are ~0.02% more likely, reducing entropy from 19.78 bits to 19.78 bits (loss < 0.001 bits — negligible). BLE PIN range also incorrectly excludes 999999 (should be `nextInt(100000, 1000000)`). All firmware roles are potentially affected if a div-by-zero caller is added.

**Description:**  
The modulo operation `num % (_max - _min)` introduces bias when the range doesn't divide evenly into 2^32. More critically, if `_max == _min`, the expression becomes `num % 0`, which is undefined behavior in C++ — on most embedded platforms this causes a hardware fault / crash / hang.

**Code:**
```cpp
// Utils.cpp
uint32_t RNG::nextInt(uint32_t _min, uint32_t _max) {
  uint32_t num;
  random((uint8_t *) &num, sizeof(num));
  return (num % (_max - _min)) + _min;  // ← div-by-zero if _max == _min
}
```

**Code (BLE PIN — excluded range):**
```cpp
// companion_radio/MyMesh.cpp
  _active_ble_pin = rng.nextInt(100000, 999999); // ← excludes 999999; should be 1000000
```

**All current callers (safe in stock firmware):**
| Call Site | _min | _max | Purpose |
|-----------|------|------|--------|
| `Mesh.cpp getRetransmitDelay` | 0 | 5 | Retransmit jitter |
| `Mesh.cpp getCADFailRetryDelay` | 1 | 4 | CAD retry delay |
| `SensorMesh.cpp` | 0 | 6 | Sensor retransmit |
| `MyMesh.cpp` (repeater/room/companion) | 0 | 5*t+1 | Retransmit jitter |
| `MyMesh.cpp` (companion BLE) | 100000 | 999999 | BLE pairing PIN |

---

### Bug #16 — LOW: No Replay Protection in Encrypt-then-MAC Scheme

**File:** `src/Utils.cpp`  
**Impact:** Previously captured packets can be replayed after the `hasSeen` hash table cycles.

**Description:**  
The encrypt-then-MAC scheme uses only the shared secret for HMAC — no sequence number, nonce, or timestamp participates in the MAC. While the `SimpleMeshTables::hasSeen()` table provides deduplication, it is a small cyclic buffer (128 entries). After enough new packets are seen, old entries are evicted and a replayed packet will be accepted as new. This enables delayed replay attacks.

---

### Bug #17 — LOW: `IdentityStore` Buffer Overflow in Filename Construction

**File:** `src/helpers/IdentityStore.cpp`  
**Impact:** Stack buffer overflow if directory path + name exceeds ~34 characters.

**Worst-Case Outcome:** **Latent stack overflow** -- not triggerable in current firmware. All four methods (`load` x2, `save` x2) use `sprintf(filename, "%s/%s.id", _dir, name)` into a `char filename[40]` stack buffer. Every call site in the codebase (26 total across all firmware variants) uses hardcoded `_dir` values (`""` on nRF52/STM32, `"/identity"` on ESP32/RP2040) and the hardcoded literal `"_main"` as `name`. The worst-case current output is `"/identity/_main.id"` = 19 bytes, well within the 40-byte buffer (21-byte margin). Neither `_dir` nor `name` is reachable from any serial, BLE, or CLI command. The bug becomes exploitable only if a future code change passes user-controlled input (e.g., contact names, CLI arguments) as the `name` parameter. A name longer than ~25 characters (with `_dir="/identity"`) would overflow the buffer by up to tens of bytes, corrupting the ARM saved registers and return address on the stack -- causing a crash or potentially controlled code execution.

**Description:**  
`sprintf(filename, "%s/%s.id", _dir, name)` writes into a 40-byte `char filename[40]` buffer with no length check. While `name` is typically set programmatically, a long `_dir` configuration string could push the total past 40 bytes.

**Code:**
```cpp
// IdentityStore.cpp -- same pattern in all four methods
bool IdentityStore::load(const char *name, mesh::LocalIdentity& id) {
  bool loaded = false;
  char filename[40];
  sprintf(filename, "%s/%s.id", _dir, name);  // <- no size check
```

**All callers verified safe:**
| Caller | _dir | name | Output bytes |
|--------|------|------|--------------|
| All nRF52/STM32 variants | `""` | `"_main"` | 10 |
| All ESP32/RP2040 variants | `"/identity"` | `"_main"` | 19 |

---

### Bug #18 — LOW: Passwords Stored Unencrypted on Flash and Echoed in CLI Replies

**File:** `src/helpers/CommonCLI.cpp`, `src/helpers/CommonCLI.h`, `src/helpers/BaseChatMesh.cpp`  
**Impact:** Admin and guest passwords stored unencrypted on flash; echoed in encrypted CLI reply packets that the admin client decrypts automatically.

**Worst-Case Outcome:** **Credential exposure** requiring admin authentication or physical access. Three vectors: (1) The `"password <new>"` CLI command echoes the new admin password in the encrypted reply: `sprintf(reply, "password now: %s", _prefs->password)`. The reply IS encrypted (AES-ECB) over the radio, but the admin's companion radio decrypts it automatically — the plaintext password appears in the meshcore_py event payload and app UI. (2) The `"get guest.password"` CLI command returns the guest password in an encrypted reply: `sprintf(reply, "> %s", _prefs->guest_password)` — again, decrypted automatically by the client. (3) Both passwords are stored as raw `char[16]` at known offsets in the `/com_prefs` flash file (admin at offset 56, guest at offset 88) with no encryption or hashing — physical access to the device allows trivial extraction. The login protocol sends the password as plaintext within AES-ECB encrypted ANON_REQ packets (`sendLogin()` in BaseChatMesh.cpp), enabling ciphertext pattern analysis (same password = same ECB block). All roles affected (repeater, room server, sensor).

**Description:**  
When an admin sets or changes the password, the reply echoes the new password in the encrypted CLI response. The `get guest.password` command returns the guest password in an encrypted reply. In both cases, the admin's companion radio decrypts the reply automatically, so the plaintext password is visible to the client software. Additionally, all passwords are stored in plaintext in the preferences file on flash — anyone with physical device access can extract credentials directly.

**Code (admin password echo):**
```cpp
// CommonCLI.cpp:284
    } else if (memcmp(command, "password ", 9) == 0) {
      StrHelper::strncpy(_prefs->password, &command[9], sizeof(_prefs->password));
      savePrefs();
      sprintf(reply, "password now: %s", _prefs->password);   // <- echoed over radio!
```

**Code (guest password retrieval):**
```cpp
// CommonCLI.cpp:754
  } else if (memcmp(config, "guest.password", 14) == 0) {
    sprintf(reply, "> %s", _prefs->guest_password);  // <- plaintext over radio
```

**Code (login sends password in payload):**
```cpp
// BaseChatMesh.cpp:558
    memcpy(&temp[4], password, len);  // <- password plaintext in encrypted packet
    pkt = createAnonDatagram(PAYLOAD_TYPE_ANON_REQ, self_id, recipient.id,
                             recipient.getSharedSecret(self_id), temp, tlen);
```

**Code (flash storage -- no encryption):**
```cpp
// CommonCLI.cpp:savePrefs()
    file.write((uint8_t *)&_prefs->password[0], sizeof(_prefs->password));       // offset 56
    file.write((uint8_t *)&_prefs->guest_password[0], sizeof(_prefs->guest_password)); // offset 88
```

---

### Bug #19 — LOW: `ftoa`/`ftoa3` Static Buffer Not Reentrant

**File:** `src/helpers/TxtDataHelpers.cpp`  
**Impact:** Corrupted output when called twice in one expression (e.g. in `sprintf` argument list).

**Worst-Case Outcome:** Latent wrong CLI response -- **not triggerable in current firmware**. All 9 call sites in `CommonCLI.cpp` use a single `ftoa`/`ftoa3` per expression, or explicitly `strcpy` to a local buffer before the next call (the "radio" getter at lines 775-777). The bug will manifest only if a future developer writes `sprintf(reply, "%s,%s", ftoa(lat), ftoa(lon))` -- since both calls return a pointer to the same `static char[16]` buffer, the second call overwrites the first, and both `%s` format arguments resolve to the same (second) value. The result is a duplicated value in the CLI response text (e.g. "3.45,3.45" instead of "1.23,3.45"). **No memory corruption, no crash, no security impact** -- only incorrect text output. The developer was clearly aware of the problem (the explicit `strcpy` workaround proves it), but the pattern is fragile and easy to misuse.

**PoC:** `bug19-ftoa-static-buffer.py`  
**Patch:** `bug19-ftoa-static-buffer.patch`

**Description:**  
Both `StrHelper::ftoa()` and `StrHelper::ftoa3()` return a pointer to a `static char` buffer. If called twice in the same `sprintf` or expression, the second call overwrites the first result before it is consumed. The `handleGetCmd` code for "radio" params works around this by copying to local buffers, but other call sites may not.

**Code:**
```cpp
// TxtDataHelpers.cpp
const char* StrHelper::ftoa(float f) {
  static char tmp[16];  // <- shared across all calls
  int status;
  _ftoa(f, tmp, &status);
  // ...
  return tmp;  // <- pointer to static buffer, next call overwrites
}

const char* StrHelper::ftoa3(float f) {
  static char s[16];  // <- same problem
  // ...
  return s;
}
```

**Severity Review:** Keeping **LOW**. The bug is entirely latent -- no current call site triggers it, and the impact if triggered is limited to wrong text in a CLI response (no memory safety issue). The fix is straightforward: change the API to accept a caller-provided buffer.

---

### Bug #20 — LOW: Serial Frame Truncation Returns Corrupt Data

**File:** `src/helpers/ArduinoSerialInterface.cpp`  
**Impact:** When oversized frames arrive, a partially-captured truncated frame is returned as valid.

**Worst-Case Outcome:** Silent data loss on long serial messages -- affects **only serial (UART) connections**, not BLE or WiFi. When a companion app or meshcore_py script sends a frame larger than `MAX_FRAME_SIZE` (172 bytes) over serial, `checkRecvFrame()` stores the first 172 bytes in `rx_buf` and discards the rest. When all `_frame_len` bytes have been read from UART, the code clamps `_frame_len` to 172 and returns the truncated buffer as a valid frame. The command handler (`handleCmdFrame`) then parses a shorter-than-intended payload. In practice, this affects `CMD_SEND_TXT_MSG` and `CMD_SEND_CHANNEL_TXT_MSG` with long text payloads -- the message is silently shortened before encryption and transmission. **No crash, no memory corruption, no security impact** -- just data loss. The `meshcore_py` library's `serial_cx.py` has no outbound size limit, so it can trigger this. The WiFi interface (`SerialWifiInterface`) already correctly rejects oversized frames with a debug log. The BLE interfaces are naturally limited by MTU.

**PoC:** `bug20-serial-truncation.py`  
**Patch:** `bug20-serial-truncation.patch`

**Description:**  
When `_frame_len > MAX_FRAME_SIZE`, the code reads bytes into `rx_buf` only up to `MAX_FRAME_SIZE` and discards the rest. But when the frame is "complete" (all `_frame_len` bytes received), it truncates `_frame_len` to `MAX_FRAME_SIZE` and returns the buffer. The problem is that `rx_buf` contains only the *first* `MAX_FRAME_SIZE` bytes, but the frame may have been longer — the caller receives a truncated, potentially malformed frame and tries to parse it.

**Code:**
```cpp
// ArduinoSerialInterface.cpp — checkRecvFrame()
      default:
        if (rx_len < MAX_FRAME_SIZE) {
          rx_buf[rx_len] = (uint8_t)c;   // rest of frame will be discarded if > MAX
        }
        rx_len++;
        if (rx_len >= _frame_len) {  // received a complete frame?
          if (_frame_len > MAX_FRAME_SIZE) _frame_len = MAX_FRAME_SIZE;    // truncate
          memcpy(dest, rx_buf, _frame_len);
          _state = RECV_STATE_IDLE;
          return _frame_len;  // <- returns truncated/corrupt data as if valid
        }
```

**Severity Review:** Keeping **LOW**. The bug only affects serial UART connections (not BLE, not WiFi). The impact is silent text truncation -- no memory safety issue, no crash, no security impact. Most real-world usage is via BLE (phone apps), which is unaffected.

---

### Bug #22 — CRITICAL: Synchronous Flash Write During `acl.save()` Blocks Radio and Causes Hang

**File:** `src/helpers/ClientACL.cpp`, `examples/simple_repeater/MyMesh.cpp` (line ~1294)  
**Impact:** Device becomes unresponsive for 200–500 ms on every login; on nRF52 with BLE this can drop the BLE connection entirely. Confirmed to cause observable "hang" on repeater login.

**Worst-Case Outcome:** **Permanent radio hang (requires reboot)** on nRF52 repeaters and room servers. When `acl.save()` triggers flash page erase via the SoftDevice, the CPU is halted for ~85 ms per page. If the SX1262 LoRa radio has an active SPI transaction at that moment, the SPI bus is corrupted — the radio enters an undefined state and **never recovers**. This chains into Bug #9 (stuck detection with no recovery). The node appears partially alive (BLE responds, serial works) but is permanently deaf to all LoRa mesh traffic. Risk scales with ACL size: more enrolled clients = more flash pages to erase/write = wider time window for SPI collision. On ESP32 the flash subsystem is less blocking, so the impact is a 200-500 ms radio blackout (temporary, not permanent). Triggered reliably ~5 seconds after any first client login to a repeater.

**Description:**  
After a successful password login, the repeater sets `dirty_contacts_expiry = futureMillis(5000)`. Five seconds later, in the main `loop()`, `acl.save(_fs)` is called. This performs a **synchronous** flash file delete + rewrite of the entire client table (up to 20 clients × 136 bytes = 2720 bytes).

On **nRF52 with SoftDevice** (BLE), the `openWrite()` function first calls `_fs->remove("/s_contacts")` which triggers a flash page erase via `sd_flash_page_erase()`. A single page erase takes ~85 ms during which the SoftDevice blocks CPU execution. Then the subsequent `file.write()` calls trigger additional flash page program operations. The total blocking time can reach **200–500 ms**.

During this entire blocking period:
1. `Dispatcher::loop()` is not called — no radio RX/TX processing occurs
2. The radio ISR may fire (setting `STATE_INT_READY`), but `recvRaw()` is never called to service it
3. If the radio was mid-transmit of the login reply, the `outbound_expiry` timer may pass, causing the reply to be marked as a TX failure
4. On nRF52 with BLE, the SoftDevice may lose BLE connection events during prolonged flash operations, causing the **BLE serial link to disconnect**
5. The 8-second "radio stuck" detector (Bug #9) doesn't help because it only sets a flag with no recovery action

Because login is the **one operation guaranteed to dirty the ACL** for a new client, this bug is triggered reliably on every first login to a repeater.

**Code (loop triggers save after 5-second delay):**
```cpp
// MyMesh.cpp — loop()
  // is pending dirty contacts write needed?
  if (dirty_contacts_expiry && millisHasNowPassed(dirty_contacts_expiry)) {
    acl.save(_fs);              // ← blocks main loop for 200-500ms!
    dirty_contacts_expiry = 0;
  }
```

**Code (save performs synchronous flash delete + write):**
```cpp
// ClientACL.cpp — openWrite() on nRF52
static File openWrite(FILESYSTEM* _fs, const char* filename) {
  #if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
    _fs->remove(filename);                    // ← flash page ERASE (~85ms per page)
    return _fs->open(filename, FILE_O_WRITE); // ← allocate new file
  #else
    return _fs->open(filename, "w", true);
  #endif
}

// ClientACL.cpp — save()
void ClientACL::save(FILESYSTEM* fs, bool (*filter)(ClientInfo*)) {
  File file = openWrite(_fs, "/s_contacts");
  if (file) {
    for (int i = 0; i < num_clients; i++) {
      auto c = &clients[i];
      // 136 bytes per client × up to 20 clients = 2720 bytes of flash writes
      file.write(c->id.pub_key, 32);       // ← each write may trigger flash page program
      file.write((uint8_t *)&c->permissions, 1);
      // ... more writes ...
      file.write(c->out_path, 64);
      file.write(c->shared_secret, PUB_KEY_SIZE);
    }
    file.close();                           // ← final flush + metadata write
  }
}
```

**Code (login sets the dirty flag):**
```cpp
// MyMesh.cpp — handleLoginReq()
    if (perms != PERM_ACL_GUEST) {
      dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY); // 5000ms
    }
```

---

## Most Likely to Cause Device Hang / Unresponsive

| Priority | Bug # | Severity | Mechanism |
|----------|-------|----------|-----------|
| 1 | **#22** | CRITICAL | `acl.save()` blocks main loop 200–500 ms — SPI corruption on nRF52 permanently kills LoRa radio; **triggered by normal first login** |
| 2 | **#1** | CRITICAL | OOB write on `data[len]=0` corrupts stack — immediate crash on receiving max-length text message |
| 3 | **#4** | HIGH | Packet pool exhaustion via flood/TRACE abuse — node permanently drops all traffic |
| 4 | **#9** | HIGH | Radio stuck in non-RX with no recovery — device permanently deaf (chains from #22) |
| 5 | **#6** | HIGH | TRACE flood drains TX budget and fills queue — node stops responding to normal messages (self-recovers) |
| 6 | **#7** | HIGH | Unbounded sprintf overflow — 30-byte stack corruption via BLE/radio CLI command |
| 7 | **#15** | LOW | `RNG::nextInt` division-by-zero if `_max == _min` — latent UB, not remotely triggerable |
