#!/usr/bin/env python3
"""Runs keylog.js against one app on your own rooted device and writes its TLS keys to a key
log Traffic AL can read (phase 11, docs/DECRYPTION.md). You then place that file in Traffic
AL's key-log path with root.

Prerequisites (on your computer): pip install frida-tools; and frida-server running on the
device (same major version as frida). The device is reached over USB (adb).

Usage: capture.py <package-name | pid> [keylog.txt]

Run it, use the app so it makes connections, then stop with Ctrl-C.
"""
import os
import sys

try:
    import frida
except ImportError:
    sys.exit("frida is not installed: pip install frida-tools")

target = sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__)
out_path = sys.argv[2] if len(sys.argv) > 2 else "keylog.txt"
out = open(out_path, "a")
script_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "keylog.js")).read()


def on_message(message, data):
    if message["type"] == "send":
        line = message["payload"]
        if line.startswith("#"):
            print(line, file=sys.stderr)  # a status note from the script
        else:
            out.write(line if line.endswith("\n") else line + "\n")
            out.flush()
    elif message["type"] == "error":
        print(message.get("stack", message), file=sys.stderr)


device = frida.get_usb_device()
started = None
try:
    started = device.spawn([target])  # a package name
    session = device.attach(started)
except frida.ExecutableNotFoundError:
    session = device.attach(target)  # an already-running process (name or pid)

script = session.create_script(script_src)
script.on("message", on_message)
script.load()
if started is not None:
    device.resume(started)

print(f"capturing TLS keys for {target} -> {out_path}; use the app, then press Ctrl-C", file=sys.stderr)
try:
    sys.stdin.read()
except KeyboardInterrupt:
    pass
