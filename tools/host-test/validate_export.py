#!/usr/bin/env python3
"""Recording check on the output of the exportCheck tool (see validate.sh): tshark must
read every exported recording without errors, with every packet, the same packet lengths
and the app comment on each packet."""
import json
import subprocess
import sys
from pathlib import Path

out = Path(sys.argv[1])
expected = json.loads((out / "export.json").read_text())
failures = []


def read(name, comments=False):
    """Frame lengths (and comments) of a capture; fails on any tshark error or warning."""
    fields = ["-e", "frame.len"] + (["-e", "frame.comment"] if comments else [])
    result = subprocess.run(
        ["tshark", "-n", "-r", str(out / name), "-T", "fields", "-E", "separator=|"] + fields,
        capture_output=True, text=True)
    # Any message but the root notice means a damaged file (e.g. "cut short in the middle").
    errors = [line for line in result.stderr.splitlines()
              if line.strip() and not line.startswith('Running as user "root"')]
    if result.returncode != 0 or errors:
        failures.append(f"{name}: tshark exit {result.returncode}: {' '.join(errors)[:300]}")
    rows = [line.split("|") for line in result.stdout.splitlines()]
    return [int(row[0]) for row in rows], [row[1] if comments else None for row in rows]


def check(condition, message):
    print(("ok   " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)


packets = expected["packets"]
lengths, comments = read("recording.pcapng", comments=True)
check(len(lengths) == packets == expected["exported"],
      f"recording: {len(lengths)}/{packets} packets in {expected['segments']} segments")
check(expected["segments"] > 1, "recording has several segments (one PCAPNG section each)")
check(all(c.startswith("uid=") for c in comments), "recording: every packet has the app comment")

limited, _ = read("recording-limited.pcapng")
size = (out / "recording-limited.pcapng").stat().st_size
check(size <= expected["limitBytes"], f"limited recording: {size} bytes <= limit {expected['limitBytes']}")
check(expected["limitedTruncated"] and 0 < len(limited) < packets,
      f"limited recording keeps the newest {len(limited)} of {packets} packets")
check(limited == lengths[-len(limited):], "limited recording is the tail of the capture")

encrypted, encrypted_comments = read("recording-encrypted.pcapng", comments=True)
check(expected["encryptedDamaged"] == 0 and encrypted == lengths and encrypted_comments == comments,
      f"encrypted recording: {len(encrypted)}/{packets} packets after decryption, same lengths and comments")
ciphertext = b"".join(p.read_bytes() for p in sorted((out / "recordings-encrypted").rglob("*.enc")))
check(b"traffic-al" not in ciphertext and b"uid=" not in ciphertext,
      "encrypted segments contain no cleartext PCAPNG")

cut, _ = read("recording-cut.pcapng")
check(expected["cutDamaged"] == 1 and 0 < len(cut) < packets and cut == lengths[:len(cut)],
      f"recording cut off while writing: {len(cut)} complete packets exported, the file stays valid")

for failure in failures:
    print("FAIL", failure)
sys.exit(1 if failures else 0)
