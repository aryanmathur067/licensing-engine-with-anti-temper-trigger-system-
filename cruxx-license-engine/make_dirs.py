import os
import pathlib

base = pathlib.Path(r"C:\Users\aryan mathur\.gemini\antigravity\scratch\cruxx-license-engine")
src_dir = base / "cruxx_license"
tests_dir = base / "tests"

for d in [
    src_dir,
    src_dir / "crypto",
    src_dir / "hardware",
    src_dir / "guard",
    src_dir / "licensing",
    tests_dir,
]:
    d.mkdir(parents=True, exist_ok=True)

print("Directories created.")
