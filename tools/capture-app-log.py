"""Bounded, PID-only, line-flushed diagnostic capture (no global logcat reset)."""
import argparse
import pathlib
import subprocess
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024)
    args = parser.parse_args()
    if args.pid <= 0 or not 1 <= args.seconds <= 1800 or not 1 <= args.max_bytes <= 8 * 1024 * 1024:
        parser.error("PID/duration/size outside bounded limits")
    # -tt makes the Android producer line-buffered. The global ring can wrap
    # within seconds on this phone; a later `logcat -d` is not reliable evidence.
    with args.output.open("xb") as output:
        child = subprocess.Popen([args.adb, "-s", args.serial, "shell", "-tt", "logcat",
                                  f"--pid={args.pid}", "-v", "threadtime", "-T", "1"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        timer = threading.Timer(args.seconds, child.terminate)
        timer.start()
        count = 0
        try:
            for line in iter(child.stdout.readline, b""):
                piece = line[:args.max_bytes - count]
                output.write(piece)
                output.flush()
                count += len(piece)
                if count >= args.max_bytes:
                    break
        finally:
            timer.cancel()
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=10)
    print(f"Captured {count} bytes for PID {args.pid} to {args.output}")


if __name__ == "__main__":
    main()
