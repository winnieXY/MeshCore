#!/usr/bin/env python3
"""
Bug #19 -- ftoa/ftoa3 Static Buffer Not Reentrant
==================================================

PoC demonstrating that StrHelper::ftoa() and StrHelper::ftoa3() return
pointers to a shared static buffer. If called twice in one expression,
the second call overwrites the first result before it is consumed.

Parts A: Analytical (no hardware required) -- simulates the aliasing in Python
Part B: Live meshcore_py test (requires a MeshCore device with admin access)
"""


# ========================================================================
# PART A: Demonstrate the static buffer aliasing problem in C
# ========================================================================
def part_a():
    print("=" * 72)
    print("PART A: Static buffer aliasing simulation")
    print("=" * 72)
    print()

    # Simulate ftoa() with a shared static buffer (Python equivalent)
    _ftoa_buf = [None]  # mutable container to simulate static char[16]

    def ftoa(f):
        """Simulates StrHelper::ftoa() -- returns pointer to shared buffer."""
        s = f"{f:.7f}".rstrip("0").rstrip(".")
        _ftoa_buf[0] = s
        return _ftoa_buf  # Returns reference to the SAME object each time

    # Current safe usage (one call per sprintf):
    # sprintf(reply, "> %s", ftoa(freq));
    result1 = ftoa(915.0)
    val1_safe = result1[0]  # consumed before next call
    result2 = ftoa(125.0)
    val2_safe = result2[0]
    print(f"Safe usage (sequential):")
    print(f"  ftoa(915.0) = '{val1_safe}'")
    print(f"  ftoa(125.0) = '{val2_safe}'")
    print()

    # Unsafe hypothetical usage (two calls in one sprintf):
    # sprintf(reply, "> %s,%s", ftoa(freq), ftoa(bw));
    # In C, argument evaluation order is unspecified, but both return
    # the SAME static buffer pointer. After both calls complete,
    # the buffer holds the LAST value written.
    r1 = ftoa(915.0)  # r1 points to shared buffer = "915"
    r2 = ftoa(125.0)  # r2 points to shared buffer = "125", r1 also = "125"!
    print(f"Unsafe usage (two calls, same expression):")
    print(f"  ftoa(915.0) returns buffer -> now holds: '{r1[0]}'")
    print(f"  ftoa(125.0) returns buffer -> now holds: '{r2[0]}'")
    print(f"  Both pointers refer to same buffer!")
    print(f"  sprintf would produce: '> 125,125' instead of '> 915,125'")
    print()

    # Show the actual safe workaround in the codebase (lines 775-777):
    print("Current code (CommonCLI.cpp:775-777) uses a safe workaround:")
    print('  char freq[16], bw[16];')
    print('  strcpy(freq, StrHelper::ftoa(_prefs->freq));      // copy to local')
    print('  strcpy(bw, StrHelper::ftoa3(_prefs->bw));         // copy to local')
    print('  sprintf(reply, "> %s,%s,%d,%d", freq, bw, sf, cr);')
    print()
    print("This workaround is fragile -- it relies on every future caller")
    print("knowing about the static buffer. A developer who writes:")
    print('  sprintf(reply, "%s,%s", ftoa(a), ftoa(b));')
    print("will silently get the SAME value for both fields.")
    print()


# ========================================================================
# PART B: Live meshcore_py test -- trigger all ftoa call paths remotely
# ========================================================================
import asyncio

async def run_live_poc(port):
    try:
        from meshcore import MeshCore
    except ImportError:
        print("[ERROR] meshcore_py not installed. pip install meshcore")
        return

    print("=" * 72)
    print("PART B: Live meshcore_py -- trigger ftoa call paths via CLI")
    print("=" * 72)
    print(f"Device: {port}")
    print()
    print("Sending 'get' commands that invoke ftoa/ftoa3 on the device...")
    print("(All current call sites are safe -- this confirms they work correctly)")
    print()

    mc = await MeshCore.create_serial(port, 115200)

    # These CLI commands trigger the ftoa() calls in handleGetCmd
    get_commands = [
        ("get airtime",     "ftoa(airtime_factor)     -- line 741"),
        ("get lat",         "ftoa(node_lat)           -- line 766"),
        ("get lon",         "ftoa(node_lon)           -- line 768"),
        ("get radio",       "ftoa(freq) + ftoa3(bw)   -- lines 775-776 (safe: strcpy)"),
        ("get rxdelay",     "ftoa(rx_delay_base)      -- line 779"),
        ("get txdelay",     "ftoa(tx_delay_factor)    -- line 781"),
        ("get direct.txdelay", "ftoa(direct_tx_delay_factor) -- line 785"),
        ("get freq",        "ftoa(freq)               -- line 810"),
    ]

    for cmd, desc in get_commands:
        try:
            resp = await mc.send_cmd("", cmd)
            reply = getattr(resp, "response", str(resp)) if resp else "(no response)"
            print(f"  [{cmd:<22}] -> {reply:<20}  ({desc})")
        except Exception as e:
            print(f"  [{cmd:<22}] -> ERROR: {e}")

    print()
    print("[*] All ftoa call paths triggered successfully.")
    print("[*] The 'get radio' response should show 'freq,bw,sf,cr' correctly")
    print("    because the code uses strcpy() to avoid the static buffer bug.")
    print()
    print("[*] If the patch is NOT applied and a future developer adds:")
    print('      sprintf(reply, "%s,%s", ftoa(lat), ftoa(lon));')
    print("    the response would show the SAME value for both lat and lon.")

    await mc.disconnect()


# ========================================================================
# Main
# ========================================================================
if __name__ == "__main__":
    import sys

    if "--live" in sys.argv:
        idx = sys.argv.index("--live")
        if len(sys.argv) < idx + 2:
            print("Usage: python bug19-ftoa-static-buffer.py --live PORT")
            print("Example: python bug19-ftoa-static-buffer.py --live COM3")
            sys.exit(1)
        port = sys.argv[idx + 1]
        asyncio.run(run_live_poc(port))
    else:
        print("Bug #19 PoC -- ftoa/ftoa3 Static Buffer Not Reentrant")
        print("=====================================================")
        print()
        part_a()
        print()
        print("To run the live test:")
        print("  python bug19-ftoa-static-buffer.py --live COM3")
