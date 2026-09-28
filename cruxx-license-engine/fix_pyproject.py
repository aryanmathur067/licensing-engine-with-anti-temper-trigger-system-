from pathlib import Path

base = Path(r"C:\Users\aryan mathur\.gemini\antigravity\scratch\cruxx-license-engine")
(base / "pyproject.toml").write_text("""[project]
name = "cruxx-license-engine"
version = "1.0.0"
description = "Defense-Grade Licensing & Anti-Tamper Engine for Cruxx Solutions & CORTA OS"
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "cryptography>=42.0.0",
]

[project.optional-dependencies]
test = [
    "pytest>=8.0.0",
]

[project.scripts]
cruxx-guard = "cruxx_license.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["cruxx_license"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
""", encoding="utf-8")
print("pyproject.toml updated.")
