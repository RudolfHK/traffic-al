"""End-to-end check of the app on an emulator (or a phone) over adb, see docs/PERFORMANCE.md.

  python3 tools/emulator/bench.py <app.apk> [result.json]

Serves a file from this machine and downloads it with `nc` in `adb shell`, without and
with the capture running. Shell traffic goes through the VPN (the app's own traffic is
excluded from it). Also measures the app's start time, CPU time, memory and frame
drops, and fails if the capture breaks the download or the app dies.
"""
import functools
import http.server
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import threading
import time

PACKAGE = "io.github.rudolfhk.traffical"
SERVICE = f"{PACKAGE}/.vpn.CaptureVpnService"
ACTIVITY = f"{PACKAGE}/.MainActivity"
SIZE_MB = int(os.environ.get("BENCH_MB", "100"))
HOST = os.environ.get("BENCH_HOST", "10.0.2.2")  # this machine, as seen from the emulator
PORT = int(os.environ.get("BENCH_PORT", "8765"))
ROUNDS = 3
MIN_SHARE = float(os.environ.get("BENCH_MIN_SHARE", "0"))  # capture throughput / direct


def adb(*args, check=True):
    return subprocess.run(["adb", *args], capture_output=True, text=True, check=check).stdout


def shell(command):
    return adb("shell", command)


def serve(directory):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
    handler.log_message = lambda *args: None
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def download():
    """Mbit/s of one download in adb shell; the time includes adb's own overhead."""
    start = time.monotonic()
    out = shell(f"printf 'GET /blob HTTP/1.0\\r\\n\\r\\n' | nc {HOST} {PORT} | wc -c")
    elapsed = time.monotonic() - start
    received = int(out.strip() or 0)
    if received < SIZE_MB * 1024 * 1024:
        raise RuntimeError(f"download incomplete: {received} bytes")
    return SIZE_MB * 8 * 1.048576 / elapsed


def downloads():
    return round(statistics.median(download() for _ in range(ROUNDS)))


def pid():
    return shell(f"pidof {PACKAGE}").strip()


def cpu_seconds(process):
    fields = shell(f"cat /proc/{process}/stat").rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / 100  # USER_HZ


def memory():
    """App memory in MB from dumpsys meminfo's App Summary."""
    out = shell(f"dumpsys meminfo {PACKAGE}")
    result = {}
    for name, key in (("Java Heap", "java_heap_mb"), ("Native Heap", "native_heap_mb"), ("TOTAL PSS", "total_pss_mb")):
        match = re.search(rf"{name}:\s+(\d+)", out)
        if match:
            result[key] = round(int(match.group(1)) / 1024, 1)
    return result


def janky_frames():
    match = re.search(r"Janky frames: (\d+) \(([\d.]+)%\)", shell(f"dumpsys gfxinfo {PACKAGE}"))
    return f"{match.group(1)} ({match.group(2)}%)" if match else None


def wait_for(condition, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.5)
    return False


def tun_up():
    # `ip link` fails for the shell user on Android 10; the interface list is readable.
    return "tun" in adb("shell", "ls /sys/class/net", check=False)


def main():
    apk = sys.argv[1]
    results = {}
    with tempfile.TemporaryDirectory() as www:
        with open(os.path.join(www, "blob"), "wb") as f:
            f.write(os.urandom(SIZE_MB * 1024 * 1024))
        serve(www)

        adb("install", "-r", "-g", apk)
        shell(f"appops set {PACKAGE} ACTIVATE_VPN allow")
        print("nc:", shell("which nc").strip() or "missing", file=sys.stderr)

        # Cold start: the activity's first frame, from a stopped process.
        shell(f"am force-stop {PACKAGE}")
        start = shell(f"am start -W -n {ACTIVITY}")
        match = re.search(r"TotalTime: (\d+)", start)
        results["cold_start_ms"] = int(match.group(1)) if match else None
        time.sleep(2)
        shell(f"am force-stop {PACKAGE}")

        results["download_direct_mbps"] = downloads()

        # The VPN service only accepts the system as caller: start it as root (emulator su).
        shell(f"su 0 am start-foreground-service -n {SERVICE} -a {PACKAGE}.START")
        if not wait_for(tun_up):
            raise RuntimeError("the VPN did not start")
        time.sleep(2)
        process = pid()
        cpu = cpu_seconds(process)
        started = time.monotonic()
        results["download_capture_mbps"] = downloads()
        results["download_capture_app_cpu_share"] = round((cpu_seconds(process) - cpu) / (time.monotonic() - started), 2)
        results["memory_capture_background"] = memory()

        # The same with the app on screen: the dashboard and the connection list update.
        shell(f"am start -n {ACTIVITY}")
        time.sleep(3)
        shell(f"dumpsys gfxinfo {PACKAGE} reset")
        results["download_capture_app_open_mbps"] = downloads()
        results["janky_frames_app_open"] = janky_frames()
        results["memory_capture_app_open"] = memory()

        results["app_process_survived"] = pid() == process
        results["download_capture_share"] = round(results["download_capture_mbps"] / results["download_direct_mbps"], 2)

        shell(f"su 0 am startservice -n {SERVICE} -a {PACKAGE}.STOP")
        wait_for(lambda: not tun_up(), 10)

    # The pipeline measurement of PerformanceTest, if it ran on this device before.
    log = adb("logcat", "-d", "-s", "TrafficAlPerf:I", check=False)
    found = re.findall(r"TrafficAlPerf: (\{.*\})", log)
    if found:
        results["art_pipeline"] = json.loads(found[-1])

    text = json.dumps(results, indent=2)
    print(text)
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w") as f:
            f.write(text + "\n")

    failures = []
    if not results["app_process_survived"]:
        failures.append("the app process died during the capture")
    if results["download_capture_share"] < MIN_SHARE:
        failures.append(f"capture throughput below {MIN_SHARE:.0%} of the direct download")
    for failure in failures:
        print("FAILED:", failure, file=sys.stderr)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
