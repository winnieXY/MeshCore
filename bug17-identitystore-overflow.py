#!/usr/bin/env python3
"""
Bug #17 -- PoC: IdentityStore sprintf Buffer Overflow in Filename Construction

Vulnerability
=============
All four methods in IdentityStore.cpp (load x2, save x2) use:

    char filename[40];
    sprintf(filename, "%s/%s.id", _dir, name);

The 40-byte stack buffer can overflow if len(_dir) + len(name) + 5 > 40
(5 = 1 '/' + 3 '.id' + 1 null terminator).

Current firmware values
-----------------------
    _dir:  "" (nRF52/STM32) or "/identity" (ESP32/RP2040) -- hardcoded
    name:  "_main" -- hardcoded in ALL callers

    Worst current case: "/identity" + "/" + "_main" + ".id" + '\0'
                        = 9 + 1 + 5 + 3 + 1 = 19 bytes (well within 40)

Attack surface
--------------
    - _dir is set at compile time in IdentityStore constructors -- NOT
      controllable at runtime or over the network.
    - name is always the hardcoded literal "_main" in every caller.
    - No CLI command, serial API, or BLE command passes user input to
      IdentityStore::load() or save() as the name parameter.

Conclusion:  This is a latent bug -- the unsafe sprintf pattern exists but
             cannot be triggered in current firmware.  It becomes exploitable
             only if a future code change passes user-controlled strings to
             _dir or name.

This PoC:
  Part A -- Demonstrates the overflow math and buffer boundaries
  Part B -- Shows stack layout and corruption for theoretical overflow
  Part C -- Verifies all current callers are safe
"""

import struct
import os

BUFFER_SIZE = 40
FORMAT_OVERHEAD = 5  # '/' + '.id' + '\0'


# ==================================================================
# Part A -- Buffer boundary analysis
# ==================================================================
print("=" * 70)
print("Part A: Buffer boundary analysis")
print("=" * 70)

# All observed (_dir, name) pairs from firmware source
observed_pairs = [
    ("",          "_main", "nRF52/STM32 all variants"),
    ("/identity", "_main", "ESP32/RP2040 all variants"),
]

print(f"  Buffer size: {BUFFER_SIZE} bytes")
print(f"  Format: sprintf(filename, \"%s/%s.id\", _dir, name)")
print(f"  Fixed overhead: '/' + '.id' + '\\0' = {FORMAT_OVERHEAD} bytes")
print(f"  Max safe _dir+name length: {BUFFER_SIZE - FORMAT_OVERHEAD} = {BUFFER_SIZE - FORMAT_OVERHEAD} bytes")
print()

for _dir, name, platform in observed_pairs:
    result = f"{_dir}/{name}.id"
    total = len(result) + 1  # +1 for null terminator
    margin = BUFFER_SIZE - total
    status = "SAFE" if margin > 0 else "OVERFLOW"
    print(f"  [{status:>8}] {platform}")
    print(f"            _dir={repr(_dir)} ({len(_dir)} bytes)")
    print(f"            name={repr(name)} ({len(name)} bytes)")
    print(f"            result=\"{result}\" ({total} bytes with \\0)")
    print(f"            margin: {margin} bytes remaining")
    print()


# ==================================================================
# Part B -- Theoretical overflow demonstration
# ==================================================================
print("=" * 70)
print("Part B: Theoretical overflow scenario")
print("=" * 70)

# Simulate what happens if someone passes a long _dir or name
test_cases = [
    # (_dir, name, description)
    ("/identity", "_main",
     "Current worst case (safe)"),
    ("/data/meshcore/identities", "_main",
     "Hypothetical long _dir"),
    ("/identity", "contact_AABBCCDDEEFF0011223344",
     "Hypothetical long name from user input"),
    ("/very/long/path/to/ids", "long_contact_name_here",
     "Both long (overflow)"),
]

for _dir, name, desc in test_cases:
    result = f"{_dir}/{name}.id"
    total = len(result) + 1  # +1 for null
    overflow = total - BUFFER_SIZE
    print(f"  Case: {desc}")
    print(f"    _dir  = {repr(_dir)} ({len(_dir)} bytes)")
    print(f"    name  = {repr(name)} ({len(name)} bytes)")
    print(f"    output= \"{result}\" ({len(result)} chars + \\0 = {total} bytes)")
    if overflow > 0:
        print(f"    [!] OVERFLOW: {overflow} bytes past buffer end")
        print(f"    [!] Overwrites {overflow} bytes of adjacent stack data")
        print(f"    [!] On ARM Cortex-M4: may corrupt saved registers / return address")
    else:
        print(f"    [ok] Within bounds, {-overflow} bytes of margin")
    print()

# Show the stack layout
print("  Stack layout around filename[40]:")
print("  +--------+------------------------------------------+")
print("  | offset | contents                                 |")
print("  +--------+------------------------------------------+")
print("  | [0-39] | char filename[40]                        |")
print("  | [40]   | <adjacent local variables>               |")
print("  | [40+N] | saved frame pointer (r7 on ARM)          |")
print("  | [40+M] | return address (LR on ARM)               |")
print("  +--------+------------------------------------------+")
print("  sprintf overflow writes past [39] into saved registers")
print()


# ==================================================================
# Part C -- Verify all current callers are safe
# ==================================================================
print("=" * 70)
print("Part C: Exhaustive caller verification")
print("=" * 70)

# All callers found in codebase exploration
callers = [
    ("examples/kiss_modem/main.cpp:46",          "", "_main", "load"),
    ("examples/kiss_modem/main.cpp:51",          "", "_main", "save"),
    ("examples/kiss_modem/main.cpp:46",          "/identity", "_main", "load"),
    ("examples/kiss_modem/main.cpp:51",          "/identity", "_main", "save"),
    ("examples/simple_repeater/main.cpp:79",     "", "_main", "load"),
    ("examples/simple_repeater/main.cpp:86",     "", "_main", "save"),
    ("examples/simple_repeater/main.cpp:79",     "/identity", "_main", "load"),
    ("examples/simple_repeater/main.cpp:86",     "/identity", "_main", "save"),
    ("examples/simple_repeater/MyMesh.cpp:1159", "", "_main", "save"),
    ("examples/simple_repeater/MyMesh.cpp:1159", "/identity", "_main", "save"),
    ("examples/simple_sensor/main.cpp:90",       "", "_main", "load"),
    ("examples/simple_sensor/main.cpp:97",       "", "_main", "save"),
    ("examples/simple_sensor/main.cpp:90",       "/identity", "_main", "load"),
    ("examples/simple_sensor/main.cpp:97",       "/identity", "_main", "save"),
    ("examples/simple_room_server/main.cpp:57",  "", "_main", "load"),
    ("examples/simple_room_server/main.cpp:63",  "", "_main", "save"),
    ("examples/simple_room_server/main.cpp:57",  "/identity", "_main", "load"),
    ("examples/simple_room_server/main.cpp:63",  "/identity", "_main", "save"),
    ("examples/companion_radio/DataStore.cpp:185","", "_main", "load"),
    ("examples/companion_radio/DataStore.cpp:189","", "_main", "save"),
    ("examples/companion_radio/DataStore.cpp:185","/identity", "_main", "load"),
    ("examples/companion_radio/DataStore.cpp:189","/identity", "_main", "save"),
    ("examples/simple_secure_chat/main.cpp:309", "", "_main", "load"),
    ("examples/simple_secure_chat/main.cpp:323", "", "_main", "save"),
    ("examples/simple_secure_chat/main.cpp:309", "/identity", "_main", "load"),
    ("examples/simple_secure_chat/main.cpp:323", "/identity", "_main", "save"),
]

all_safe = True
for location, _dir, name, method in callers:
    result = f"{_dir}/{name}.id"
    total = len(result) + 1
    if total > BUFFER_SIZE:
        print(f"  [OVERFLOW] {location}: {method}(\"{name}\") with _dir=\"{_dir}\" -> {total} bytes")
        all_safe = False

if all_safe:
    print(f"  All {len(callers)} call sites verified SAFE")
    print(f"  Max output: 19 bytes (with _dir=\"/identity\", name=\"_main\")")
    print(f"  Buffer: 40 bytes -> 21 bytes of margin at worst")
else:
    print(f"  [!] SOME CALLERS OVERFLOW!")

print()


# ==================================================================
# Summary
# ==================================================================
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print("""
Bug: sprintf(filename, "%s/%s.id", _dir, name) into char filename[40]

Current risk: NONE -- both _dir and name are hardcoded at compile time.
  _dir:  "" or "/identity" (set in IdentityStore constructors)
  name:  "_main" (set in every caller)
  Max output: 19 bytes << 40-byte buffer

Latent risk: If a future code change passes user-controlled strings
  (e.g. contact names, CLI input) as the 'name' parameter, the
  40-byte buffer overflows with names longer than ~25 characters.

Severity: LOW
  - Not remotely triggerable
  - Not triggerable via any current API (serial, BLE, CLI)
  - Both parameters are compile-time constants
  - Fix is simple: snprintf with sizeof(filename)
""")
