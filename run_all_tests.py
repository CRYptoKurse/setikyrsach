import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

print("=== SETI PROJECT TEST RUN ===")
print(f"Working directory: {ROOT}")
cmd = [sys.executable, "-m", "pytest", "-q", "tests"]
print(f"Command: {' '.join(cmd)}")
print("=" * 60)

result = subprocess.run(cmd, cwd=str(ROOT), text=True)
if result.stdout:
    print(result.stdout, end="")
if result.stderr:
    print(result.stderr, end="", file=sys.stderr)

print("=" * 60)
if result.returncode == 0:
    print("ALL TESTS PASSED")
else:
    print(f"TESTS FAILED (exit code: {result.returncode})")

raise SystemExit(result.returncode)
