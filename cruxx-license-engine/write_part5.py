from pathlib import Path

base = Path(r"C:\Users\aryan mathur\.gemini\antigravity\scratch\cruxx-license-engine")
lic_dir = base / "cruxx_license" / "licensing"

(lic_dir / "__init__.py").write_text('''from .schema import LicenseSchema
from .license_manager import LicenseManager

__all__ = ["LicenseSchema", "LicenseManager"]
''', encoding="utf-8")

(lic_dir / "schema.py").write_text('''"""
License Payload Schema & Specification for Cruxx Solutions Platforms
"""

import datetime
import uuid
from typing import Any, Dict, List, Optional
from ..constants import TIER_COMMERCIAL, KNOWN_MODULES


class LicenseSchema:
    """Defines structure and validations for Cruxx License Payloads."""

    @staticmethod
    def create_payload(
        customer_id: str,
        tier: str = TIER_COMMERCIAL,
        hardware_id: str = "*",
        allowed_features: Optional[List[str]] = None,
        days_valid: int = 365,
        max_fleet_size: int = 1,
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now = datetime.datetime.now(datetime.timezone.utc)
        valid_until = (now + datetime.timedelta(days=days_valid)).isoformat() if days_valid > 0 else "NEVER"

        features = allowed_features if allowed_features is not None else KNOWN_MODULES

        return {
            "license_id": str(uuid.uuid4()),
            "issuer": "Cruxx Solutions Private Limited",
            "customer_id": customer_id,
            "tier": tier,
            "hardware_id": hardware_id,
            "issued_at": now.isoformat(),
            "valid_from": now.isoformat(),
            "valid_until": valid_until,
            "allowed_features": sorted(list(set(features))),
            "max_fleet_size": max_fleet_size,
            "metadata": custom_metadata or {},
        }
''', encoding="utf-8")

(lic_dir / "license_manager.py").write_text('''"""
License Manager: Loads, Verifies, and Enforces Entitlements
"""

import datetime
import json
import os
from typing import Any, Dict, Optional, Tuple
from ..constants import (
    TAMPER_CODE_SIGNATURE_MISMATCH,
    TAMPER_CODE_HARDWARE_MISMATCH,
    TAMPER_CODE_LICENSE_EXPIRED,
    TAMPER_CODE_CLOCK_ROLLBACK,
)
from ..crypto.verifier import LicenseVerifier
from ..hardware.fingerprint import HardwareFingerprint


class LicenseManager:
    """
    Loads and validates digitally signed Cruxx licenses.
    Enforces hardware locks, expiration dates, and feature access.
    """

    def __init__(self, verifier: LicenseVerifier):
        self.verifier = verifier
        self.active_license_payload: Optional[Dict[str, Any]] = None
        self._last_checked_time: Optional[datetime.datetime] = None

    def load_from_file(self, license_file_path: str) -> Dict[str, Any]:
        """Loads license file from path."""
        if not os.path.exists(license_file_path):
            raise FileNotFoundError(f"License file not found: {license_file_path}")
        with open(license_file_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        return self.load_from_bundle(bundle)

    def load_from_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Validates cryptographic signature and sets active license."""
        is_valid, payload = self.verifier.verify_signed_bundle(bundle)
        if not is_valid or not payload:
            raise ValueError("License digital signature verification failed! License corrupted or forged.")
        self.active_license_payload = payload
        return payload

    def validate_license(self, hwid: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates the currently active license:
        - Checks hardware binding
        - Checks expiration
        - Checks clock rollback
        """
        if not self.active_license_payload:
            return False, "NO_LICENSE_LOADED", {}

        payload = self.active_license_payload
        current_time = datetime.datetime.now(datetime.timezone.utc)

        # 1. Clock Rollback Detection
        if self._last_checked_time and current_time < self._last_checked_time:
            return False, TAMPER_CODE_CLOCK_ROLLBACK, {
                "last_time": self._last_checked_time.isoformat(),
                "current_time": current_time.isoformat(),
            }
        self._last_checked_time = current_time

        # 2. Hardware Binding Check
        target_hwid = payload.get("hardware_id", "*")
        current_hwid = hwid or HardwareFingerprint.get_fingerprint()
        if not HardwareFingerprint.matches(target_hwid, current_hwid):
            return False, TAMPER_CODE_HARDWARE_MISMATCH, {
                "expected_hwid": target_hwid,
                "actual_hwid": current_hwid,
            }

        # 3. Validity Date Range Check
        valid_from_str = payload.get("valid_from")
        valid_until_str = payload.get("valid_until")

        if valid_from_str:
            valid_from = datetime.datetime.fromisoformat(valid_from_str)
            if current_time < valid_from:
                return False, "LICENSE_NOT_YET_VALID", {"valid_from": valid_from_str}

        if valid_until_str and valid_until_str != "NEVER":
            valid_until = datetime.datetime.fromisoformat(valid_until_str)
            if current_time > valid_until:
                return False, TAMPER_CODE_LICENSE_EXPIRED, {"expired_at": valid_until_str}

        return True, "ACTIVE", payload

    def is_feature_allowed(self, feature_name: str) -> bool:
        """Checks if a specific feature is granted under active license."""
        if not self.active_license_payload:
            return False
        allowed = self.active_license_payload.get("allowed_features", [])
        return ("*" in allowed) or (feature_name in allowed)
''', encoding="utf-8")

print("Part 5 written successfully.")
