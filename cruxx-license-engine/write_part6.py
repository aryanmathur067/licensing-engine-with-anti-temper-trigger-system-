from pathlib import Path

base = Path(r"C:\Users\aryan mathur\.gemini\antigravity\scratch\cruxx-license-engine")
pkg = base / "cruxx_license"

(pkg / "engine.py").write_text('''"""
CORTA LicenseGuard Engine: Unified Orchestrator for Cruxx Systems
"""

import functools
import json
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from .crypto.verifier import LicenseVerifier
from .guard.integrity_verifier import CodeIntegrityVerifier
from .guard.lockout_circuit_breaker import (
    LockoutCircuitBreaker,
    CruxxSecurityException,
    CruxxTamperLockoutError,
    CruxxLicenseInvalidError,
    CruxxIntegrityViolationError,
)
from .hardware.fingerprint import HardwareFingerprint
from .licensing.license_manager import LicenseManager


# Global engine singleton for decorator access
_GLOBAL_GUARD: Optional["CORTALicenseGuard"] = None


class CORTALicenseGuard:
    """
    The master security guardian for Cruxx UAV Platforms & CORTA OS.
    Guarantees zero-trust execution, continuous integrity verification,
    and instantaneous fail-secure lockout upon tamper.
    """

    def __init__(
        self,
        public_key_pem_or_path: str,
        codebase_root_dir: Optional[str] = None,
        manifest_path: Optional[str] = None,
        license_path: Optional[str] = None,
        lockout_file_path: Optional[str] = None,
        auto_lockout_on_tamper: bool = True,
        strict_untracked_files: bool = False,
    ):
        global _GLOBAL_GUARD
        self.codebase_root_dir = os.path.abspath(codebase_root_dir or ".")
        self.manifest_path = os.path.abspath(manifest_path) if manifest_path else None
        self.license_path = os.path.abspath(license_path) if license_path else None
        self.auto_lockout_on_tamper = auto_lockout_on_tamper
        self.strict_untracked_files = strict_untracked_files

        # Load Verifier
        if os.path.exists(public_key_pem_or_path):
            self.verifier = LicenseVerifier.from_file(public_key_pem_or_path)
        else:
            self.verifier = LicenseVerifier(public_key_pem_or_path)

        # Initialize Circuit Breaker & Managers
        self.circuit_breaker = LockoutCircuitBreaker(lockout_file_path)
        self.license_manager = LicenseManager(self.verifier)
        self.hwid = HardwareFingerprint.get_fingerprint()

        # Watchdog Thread
        self._watchdog_thread: Optional[threading.Thread] = None
        self._stop_watchdog = threading.Event()

        _GLOBAL_GUARD = self

    @classmethod
    def get_instance(cls) -> "CORTALicenseGuard":
        global _GLOBAL_GUARD
        if _GLOBAL_GUARD is None:
            raise CruxxSecurityException("CORTALicenseGuard has not been initialized.")
        return _GLOBAL_GUARD

    def verify_all(self) -> Dict[str, Any]:
        """
        Performs a full zero-trust security audit:
        1. Checks persistent lockout state.
        2. Validates License & Hardware binding.
        3. Validates Codebase SHA-256 integrity against signed manifest.
        Triggers instant lockout if any step fails.
        """
        # 1. Lockout Check
        is_locked, lock_data = self.circuit_breaker.is_locked_out()
        if is_locked:
            raise CruxxTamperLockoutError(
                f"SYSTEM LOCKED OUT: {lock_data.get('reason_code') or lock_data.get('reason')}. Incident nonce: {lock_data.get('incident_nonce')}"
            )

        # 2. License Check
        if self.license_path:
            if not os.path.exists(self.license_path):
                self._handle_violation("LICENSE_FILE_MISSING", {"path": self.license_path})
            try:
                self.license_manager.load_from_file(self.license_path)
            except Exception as e:
                self._handle_violation("LICENSE_CORRUPTED_OR_TAMPERED", {"error": str(e)})

            is_valid, reason, lic_data = self.license_manager.validate_license(self.hwid)
            if not is_valid:
                self._handle_violation(reason, lic_data)

        # 3. Code Integrity Check
        if self.manifest_path and os.path.exists(self.manifest_path):
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                manifest_bundle = json.load(f)

            is_ok, reason, details = CodeIntegrityVerifier.verify_directory_integrity(
                root_dir=self.codebase_root_dir,
                manifest_bundle=manifest_bundle,
                verifier=self.verifier,
                strict_untracked=self.strict_untracked_files,
            )
            if not is_ok:
                self._handle_violation(reason, details)

        return {
            "status": "HEALTHY",
            "hardware_id": self.hwid,
            "license": self.license_manager.active_license_payload,
            "integrity": "VERIFIED",
        }

    def _handle_violation(self, reason_code: str, details: Dict[str, Any]):
        if self.auto_lockout_on_tamper:
            self.circuit_breaker.trip_lockout(reason_code, details, self.hwid)
        else:
            raise CruxxIntegrityViolationError(f"Security Violation: {reason_code} - {details}")

    def check_feature(self, feature_name: str) -> bool:
        """Checks feature entitlement after full security validation."""
        is_locked, _ = self.circuit_breaker.is_locked_out()
        if is_locked:
            raise CruxxTamperLockoutError("Cannot check feature: System is in Tamper Lockout mode!")

        return self.license_manager.is_feature_allowed(feature_name)

    def start_watchdog(self, interval_seconds: int = 15):
        """Starts background watchdog thread for real-time in-flight integrity checking."""
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            return

        self._stop_watchdog.clear()

        def _watchdog_loop():
            while not self._stop_watchdog.is_set():
                try:
                    self.verify_all()
                except CruxxTamperLockoutError:
                    break
                except Exception:
                    pass
                time.sleep(interval_seconds)

        self._watchdog_thread = threading.Thread(target=_watchdog_loop, daemon=True, name="CruxxSecurityWatchdog")
        self._watchdog_thread.start()

    def stop_watchdog(self):
        """Stops background watchdog thread."""
        self._stop_watchdog.set()
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=2.0)


def require_feature(feature_name: str):
    """
    Decorator to gate critical functions/services with license check & integrity guard.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            guard = CORTALicenseGuard.get_instance()
            # Verify system integrity
            guard.verify_all()

            # Check feature entitlement
            if not guard.check_feature(feature_name):
                raise CruxxLicenseInvalidError(
                    f"Feature '{feature_name}' is not licensed for this device (Tier: {guard.license_manager.active_license_payload.get('tier') if guard.license_manager.active_license_payload else 'NONE'})."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator
''', encoding="utf-8")

print("Part 6 written successfully.")
