from pathlib import Path

base = Path(r"C:\Users\aryan mathur\.gemini\antigravity\scratch\cruxx-license-engine")
guard_dir = base / "cruxx_license" / "guard"

(guard_dir / "__init__.py").write_text('''from .integrity_verifier import CodeIntegrityVerifier
from .lockout_circuit_breaker import (
    LockoutCircuitBreaker,
    CruxxSecurityException,
    CruxxTamperLockoutError,
    CruxxLicenseInvalidError,
    CruxxIntegrityViolationError,
)

__all__ = [
    "CodeIntegrityVerifier",
    "LockoutCircuitBreaker",
    "CruxxSecurityException",
    "CruxxTamperLockoutError",
    "CruxxLicenseInvalidError",
    "CruxxIntegrityViolationError",
]
''', encoding="utf-8")

(guard_dir / "integrity_verifier.py").write_text('''"""
SHA-256 Codebase Integrity Verifier & Manifest Signer for CORTA OS Modules
"""

import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple
from ..constants import (
    TAMPER_CODE_FILE_MODIFIED,
    TAMPER_CODE_FILE_MISSING,
    TAMPER_CODE_FILE_UNTRACKED,
    TAMPER_CODE_MANIFEST_INVALID,
)
from ..crypto.verifier import LicenseVerifier, canonical_json_bytes
from ..crypto.signer import LicenseSigner


def calculate_file_sha256(filepath: str) -> str:
    """Calculates SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


class CodeIntegrityVerifier:
    """
    Manages codebase integrity manifests and verifies real-time SHA-256 hashes
    of all source code, binaries, and configurations.
    """

    DEFAULT_IGNORES = [
        "__pycache__",
        ".git",
        ".pytest_cache",
        ".corta_lockout.bin",
        "corta_manifest.json",
        ".DS_Store",
        ".venv",
        "*.pyc",
        "*.pyo",
        "*.pyd",
    ]

    @classmethod
    def should_ignore(cls, filename: str, extra_ignores: Optional[List[str]] = None) -> bool:
        ignores = cls.DEFAULT_IGNORES + (extra_ignores or [])
        for pat in ignores:
            if pat.startswith("*.") and filename.endswith(pat[1:]):
                return True
            if filename == pat or filename.startswith(pat):
                return True
        return False

    @classmethod
    def scan_directory(cls, root_dir: str, extra_ignores: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """
        Scans a directory and maps relative path -> {sha256, size_bytes}.
        """
        file_map = {}
        root_dir = os.path.abspath(root_dir)

        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Prune ignored directories
            dirnames[:] = [d for d in dirnames if not cls.should_ignore(d, extra_ignores)]
            for fname in filenames:
                if cls.should_ignore(fname, extra_ignores):
                    continue
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, root_dir).replace("\\\\", "/")
                file_hash = calculate_file_sha256(full_path)
                file_size = os.path.getsize(full_path)
                file_map[rel_path] = {
                    "sha256": file_hash,
                    "size": file_size,
                }
        return file_map

    @classmethod
    def create_signed_manifest(
        cls,
        root_dir: str,
        signer: LicenseSigner,
        version: str = "1.0.0",
        metadata: Optional[Dict[str, Any]] = None,
        extra_ignores: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generates a digitally signed manifest bundle for a directory.
        """
        files_map = cls.scan_directory(root_dir, extra_ignores)
        # Compute root hash of all files
        combined_str = "".join(f"{k}:{v['sha256']}" for k, v in sorted(files_map.items()))
        root_sha256 = hashlib.sha256(combined_str.encode("utf-8")).hexdigest()

        payload = {
            "version": version,
            "root_sha256": root_sha256,
            "file_count": len(files_map),
            "files": files_map,
            "metadata": metadata or {},
        }
        return signer.sign_payload(payload)

    @classmethod
    def verify_directory_integrity(
        cls,
        root_dir: str,
        manifest_bundle: Dict[str, Any],
        verifier: LicenseVerifier,
        strict_untracked: bool = False,
        extra_ignores: Optional[List[str]] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verifies directory against signed manifest:
        1. Validates manifest signature using Cruxx public key.
        2. Validates SHA-256 for each tracked file.
        3. Checks for missing files or modified content.
        4. Optionally checks for untracked injected code.
        """
        is_valid_sig, payload = verifier.verify_signed_bundle(manifest_bundle)
        if not is_valid_sig:
            return False, TAMPER_CODE_MANIFEST_INVALID, {"reason": "Manifest digital signature verification failed"}

        tracked_files: Dict[str, Dict[str, Any]] = payload.get("files", {})
        root_dir = os.path.abspath(root_dir)

        # 1. Check all tracked files exist and match hashes
        for rel_path, meta in tracked_files.items():
            full_path = os.path.join(root_dir, rel_path.replace("/", os.sep))
            if not os.path.exists(full_path):
                return False, TAMPER_CODE_FILE_MISSING, {
                    "file": rel_path,
                    "expected_hash": meta.get("sha256"),
                }
            current_hash = calculate_file_sha256(full_path)
            if current_hash != meta.get("sha256"):
                return False, TAMPER_CODE_FILE_MODIFIED, {
                    "file": rel_path,
                    "expected_hash": meta.get("sha256"),
                    "actual_hash": current_hash,
                }

        # 2. Check for unauthorized/injected files
        if strict_untracked:
            current_scan = cls.scan_directory(root_dir, extra_ignores)
            for current_rel in current_scan:
                if current_rel not in tracked_files:
                    return False, TAMPER_CODE_FILE_UNTRACKED, {
                        "file": current_rel,
                        "hash": current_scan[current_rel]["sha256"],
                    }

        return True, "OK", {"file_count": len(tracked_files), "root_sha256": payload.get("root_sha256")}
''', encoding="utf-8")

(guard_dir / "lockout_circuit_breaker.py").write_text('''"""
Instant Tamper Detection, Hardware-Bound Tripwire & Lockdown Engine
"""

import datetime
import hashlib
import json
import os
import secrets
from typing import Any, Dict, Optional, Tuple
from ..constants import DEFAULT_LOCKOUT_FILE
from ..crypto.verifier import LicenseVerifier, canonical_json_bytes
from ..hardware.fingerprint import HardwareFingerprint


class CruxxSecurityException(Exception):
    """Base exception for Cruxx License & Security Engine"""
    pass


class CruxxTamperLockoutError(CruxxSecurityException):
    """Raised when the system has been tripped into a tamper lockdown state"""
    pass


class CruxxLicenseInvalidError(CruxxSecurityException):
    """Raised when a license is invalid or unauthorized"""
    pass


class CruxxIntegrityViolationError(CruxxSecurityException):
    """Raised when code or binary integrity check fails"""
    pass


class LockoutCircuitBreaker:
    """
    Fail-Secure Circuit Breaker:
    Upon any detected modification, signature forgery, or tampering:
    1. Hashes tamper incident forensics.
    2. Writes a hardware-locked tamper tripwire file (.corta_lockout.bin).
    3. Traps the system into permanent lockout.
    4. Only permits unlock via authorized Cruxx Master Key Challenge-Response.
    """

    def __init__(self, lockout_file_path: Optional[str] = None):
        self.lockout_file_path = os.path.abspath(lockout_file_path or DEFAULT_LOCKOUT_FILE)
        self._in_memory_tripped = False
        self._trip_reason: Optional[str] = None

    def is_locked_out(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Returns (is_locked, lockout_data).
        Checks both in-memory state and persistent on-disk lockout file.
        """
        if self._in_memory_tripped:
            return True, {"reason": self._trip_reason or "IN_MEMORY_TRIPPED"}

        if not os.path.exists(self.lockout_file_path):
            return False, None

        try:
            with open(self.lockout_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            seal = data.get("seal")
            payload = data.get("payload", {})
            computed_seal = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
            if seal != computed_seal:
                return True, {"reason": "CORRUPTED_TAMPER_SEAL", "details": "Lockout record modified externally"}
            return True, payload
        except Exception:
            return True, {"reason": "LOCKOUT_FILE_UNREADABLE"}

    def trip_lockout(
        self,
        reason_code: str,
        details: Optional[Dict[str, Any]] = None,
        hwid: Optional[str] = None,
    ) -> None:
        """
        INSTANT LOCKOUT TRIPWIRE:
        Persists tamper state, writes machine-bound forensic lockfile,
        and halts execution.
        """
        self._in_memory_tripped = True
        self._trip_reason = reason_code
        hwid = hwid or HardwareFingerprint.get_fingerprint()
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident_nonce = secrets.token_hex(16)

        payload = {
            "status": "SYSTEM_LOCKED_OUT",
            "reason_code": reason_code,
            "timestamp": timestamp,
            "incident_nonce": incident_nonce,
            "target_hwid": hwid,
            "details": details or {},
        }
        seal = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        lockout_record = {
            "payload": payload,
            "seal": seal,
        }

        try:
            lockout_dir = os.path.dirname(self.lockout_file_path)
            if lockout_dir:
                os.makedirs(lockout_dir, exist_ok=True)
            with open(self.lockout_file_path, "w", encoding="utf-8") as f:
                json.dump(lockout_record, f, indent=2)
        except Exception:
            pass

        raise CruxxTamperLockoutError(
            f"CRUXX DEFENSE SECURITY ALERT: SYSTEM LOCKED OUT! Reason: {reason_code}. "
            f"Tamper detected. Hardware ID: {hwid}. Incident nonce: {incident_nonce}"
        )

    def generate_unlock_challenge(self) -> Dict[str, Any]:
        """
        Generates a challenge for Cruxx HQ to authorize an unlock.
        """
        is_locked, payload = self.is_locked_out()
        if not is_locked or not payload:
            raise CruxxSecurityException("System is not currently locked out.")

        hwid = HardwareFingerprint.get_fingerprint()
        challenge = {
            "type": "CRUXX_UNLOCK_CHALLENGE",
            "challenge_nonce": payload.get("incident_nonce") or secrets.token_hex(16),
            "target_hwid": hwid,
            "lockout_reason": payload.get("reason_code"),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        return challenge

    def apply_unlock_token(
        self,
        unlock_bundle: Dict[str, Any],
        verifier: LicenseVerifier,
    ) -> bool:
        """
        Validates and applies a Cruxx Master Key signed unlock token to clear lockout.
        """
        is_valid, payload = verifier.verify_signed_bundle(unlock_bundle)
        if not is_valid:
            raise CruxxSecurityException("Invalid unlock token signature. Recovery rejected.")

        if payload.get("action") != "CRUXX_SYSTEM_UNLOCK" or payload.get("status") != "APPROVED":
            raise CruxxSecurityException("Unauthorized unlock token payload.")

        current_hwid = HardwareFingerprint.get_fingerprint()
        token_hwid = payload.get("target_hwid")
        if not HardwareFingerprint.matches(token_hwid, current_hwid):
            raise CruxxSecurityException(f"Unlock token is bound to {token_hwid}, but system is {current_hwid}")

        if os.path.exists(self.lockout_file_path):
            try:
                os.remove(self.lockout_file_path)
            except Exception:
                with open(self.lockout_file_path, "w") as f:
                    f.write("{}")
                os.remove(self.lockout_file_path)

        self._in_memory_tripped = False
        self._trip_reason = None
        return True
''', encoding="utf-8")

print("Part 4 written successfully.")
