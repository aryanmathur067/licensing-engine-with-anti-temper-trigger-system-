"""
Cruxx Solutions - CORTA LicenseGuard Engine
"""

__version__ = "1.0.0"
__author__ = "Cruxx Solutions Private Limited"

from .engine import (
    CORTALicenseGuard,
    require_feature,
    CruxxSecurityException,
    CruxxTamperLockoutError,
    CruxxLicenseInvalidError,
    CruxxIntegrityViolationError,
)

__all__ = [
    "CORTALicenseGuard",
    "require_feature",
    "CruxxSecurityException",
    "CruxxTamperLockoutError",
    "CruxxLicenseInvalidError",
    "CruxxIntegrityViolationError",
]
