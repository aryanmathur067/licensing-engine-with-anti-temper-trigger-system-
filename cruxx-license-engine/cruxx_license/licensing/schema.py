"""
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
