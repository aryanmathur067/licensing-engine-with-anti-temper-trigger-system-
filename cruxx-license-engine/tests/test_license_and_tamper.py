'''
Comprehensive Test Suite for Cruxx Solutions CORTA-LicenseGuard Engine
'''

import json
import os
import tempfile
import pytest
from cruxx_license.crypto.signer import KeyPairGenerator, LicenseSigner
from cruxx_license.crypto.verifier import LicenseVerifier
from cruxx_license.hardware.fingerprint import HardwareFingerprint
from cruxx_license.licensing.schema import LicenseSchema
from cruxx_license.licensing.license_manager import LicenseManager
from cruxx_license.guard.integrity_verifier import CodeIntegrityVerifier
from cruxx_license.guard.lockout_circuit_breaker import (
    LockoutCircuitBreaker,
    CruxxTamperLockoutError,
    CruxxSecurityException,
    CruxxLicenseInvalidError,
)
from cruxx_license.engine import CORTALicenseGuard, require_feature
from cruxx_license.constants import (
    TIER_DEFENSE,
    TAMPER_CODE_FILE_MODIFIED,
    TAMPER_CODE_HARDWARE_MISMATCH,
)


@pytest.fixture
def keys_fixture():
    priv_pem, pub_pem = KeyPairGenerator.generate_keypair()
    signer = LicenseSigner(priv_pem)
    verifier = LicenseVerifier(pub_pem)
    return {
        "priv_pem": priv_pem,
        "pub_pem": pub_pem,
        "signer": signer,
        "verifier": verifier,
    }


def test_crypto_signing_and_verification(keys_fixture):
    signer = keys_fixture["signer"]
    verifier = keys_fixture["verifier"]

    payload = {"module": "corta_core", "status": "ACTIVE", "level": 9}
    signed_bundle = signer.sign_payload(payload)

    is_valid, extracted_payload = verifier.verify_signed_bundle(signed_bundle)
    assert is_valid is True
    assert extracted_payload["module"] == "corta_core"

    # Forgery test
    tampered_bundle = dict(signed_bundle)
    tampered_bundle["payload"] = {"module": "corta_core", "status": "TAMPERED", "level": 999}
    is_valid_tampered, _ = verifier.verify_signed_bundle(tampered_bundle)
    assert is_valid_tampered is False


def test_hardware_fingerprint():
    hwid = HardwareFingerprint.get_fingerprint()
    assert hwid.startswith("CRUXX-HW-")
    assert len(hwid.split("-")) == 6  # CRUXX-HW-XXXX-XXXX-XXXX-XXXX
    assert HardwareFingerprint.matches(hwid, hwid) is True
    assert HardwareFingerprint.matches("CRUXX-HW-UNBOUND-ANY", hwid) is True
    assert HardwareFingerprint.matches("CRUXX-HW-FAKE-1111-2222-3333", hwid) is False


def test_license_creation_and_entitlements(keys_fixture):
    signer = keys_fixture["signer"]
    verifier = keys_fixture["verifier"]
    hwid = HardwareFingerprint.get_fingerprint()

    payload = LicenseSchema.create_payload(
        customer_id="Indian_MoD_Squadron_101",
        tier=TIER_DEFENSE,
        hardware_id=hwid,
        allowed_features=["corta_core", "edge_ai_vision", "bvlos_comms"],
        days_valid=365,
    )
    bundle = signer.sign_payload(payload)

    mgr = LicenseManager(verifier)
    mgr.load_from_bundle(bundle)
    is_valid, status, _ = mgr.validate_license(hwid)
    assert is_valid is True
    assert status == "ACTIVE"

    assert mgr.is_feature_allowed("edge_ai_vision") is True
    assert mgr.is_feature_allowed("bvlos_comms") is True
    assert mgr.is_feature_allowed("unlicensed_future_module") is False


def test_license_hardware_mismatch_rejection(keys_fixture):
    signer = keys_fixture["signer"]
    verifier = keys_fixture["verifier"]

    payload = LicenseSchema.create_payload(
        customer_id="Test_Corp",
        tier=TIER_DEFENSE,
        hardware_id="CRUXX-HW-0000-1111-2222-3333",
    )
    bundle = signer.sign_payload(payload)

    mgr = LicenseManager(verifier)
    mgr.load_from_bundle(bundle)
    is_valid, reason, _ = mgr.validate_license("CRUXX-HW-9999-8888-7777-6666")
    assert is_valid is False
    assert reason == TAMPER_CODE_HARDWARE_MISMATCH


def test_code_integrity_manifest_and_tamper_detection(keys_fixture):
    signer = keys_fixture["signer"]
    verifier = keys_fixture["verifier"]

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create dummy CORTA module files
        mod1 = os.path.join(tmp_dir, "flight_controller.py")
        mod2 = os.path.join(tmp_dir, "ai_perception.py")
        with open(mod1, "w") as f:
            f.write("def calculate_thrust(): return 100\n")
        with open(mod2, "w") as f:
            f.write("def track_target(): return True\n")

        # 1. Create signed manifest
        manifest_bundle = CodeIntegrityVerifier.create_signed_manifest(
            root_dir=tmp_dir,
            signer=signer,
        )

        # 2. Verify unmodified codebase
        is_ok, reason, _ = CodeIntegrityVerifier.verify_directory_integrity(
            root_dir=tmp_dir,
            manifest_bundle=manifest_bundle,
            verifier=verifier,
        )
        assert is_ok is True
        assert reason == "OK"

        # 3. TAMPER WITH CODE: modify 1 single character
        with open(mod1, "w") as f:
            f.write("def calculate_thrust(): return 999\n")

        # 4. Verification MUST fail immediately
        is_ok_tampered, reason_tampered, details = CodeIntegrityVerifier.verify_directory_integrity(
            root_dir=tmp_dir,
            manifest_bundle=manifest_bundle,
            verifier=verifier,
        )
        assert is_ok_tampered is False
        assert reason_tampered == TAMPER_CODE_FILE_MODIFIED
        assert "flight_controller.py" in details["file"]


def test_lockout_circuit_breaker_and_recovery(keys_fixture):
    signer = keys_fixture["signer"]
    verifier = keys_fixture["verifier"]

    with tempfile.TemporaryDirectory() as tmp_dir:
        lockout_file = os.path.join(tmp_dir, ".corta_lockout.bin")
        cb = LockoutCircuitBreaker(lockout_file)

        # Initially not locked out
        is_locked, _ = cb.is_locked_out()
        assert is_locked is False

        # Trip lockout
        with pytest.raises(CruxxTamperLockoutError):
            cb.trip_lockout("MANUAL_SECURITY_TEST_TRIP", {"actor": "attacker"})

        # Now locked out persistently on disk
        is_locked, lock_data = cb.is_locked_out()
        assert is_locked is True
        assert lock_data["reason_code"] == "MANUAL_SECURITY_TEST_TRIP"

        # Generate Challenge
        challenge = cb.generate_unlock_challenge()
        assert challenge["type"] == "CRUXX_UNLOCK_CHALLENGE"

        # Cruxx HQ signs Challenge
        unlock_token = signer.sign_unlock_challenge(challenge)

        # Apply Recovery Token
        success = cb.apply_unlock_token(unlock_token, verifier)
        assert success is True

        # System is restored
        is_locked_after, _ = cb.is_locked_out()
        assert is_locked_after is False


def test_corta_guard_runtime_and_decorator(keys_fixture):
    signer = keys_fixture["signer"]
    pub_pem = keys_fixture["pub_pem"]

    with tempfile.TemporaryDirectory() as tmp_dir:
        pub_path = os.path.join(tmp_dir, "cruxx_public_key.pem")
        lic_path = os.path.join(tmp_dir, "corta.lic")
        mani_path = os.path.join(tmp_dir, "corta_manifest.json")
        lockout_path = os.path.join(tmp_dir, ".corta_lockout.bin")
        code_file = os.path.join(tmp_dir, "core_flight.py")

        with open(pub_path, "wb") as f:
            f.write(pub_pem)
        with open(code_file, "w") as f:
            f.write("def fly(): return 'AIRBORNE'\n")

        # Manifest
        manifest = CodeIntegrityVerifier.create_signed_manifest(tmp_dir, signer)
        with open(mani_path, "w") as f:
            json.dump(manifest, f)

        # License
        lic_payload = LicenseSchema.create_payload(
            customer_id="Cruxx_Aero_Testing",
            tier=TIER_DEFENSE,
            hardware_id="*",
            allowed_features=["corta_core", "edge_ai_vision"],
        )
        lic_bundle = signer.sign_payload(lic_payload)
        with open(lic_path, "w") as f:
            json.dump(lic_bundle, f)

        # Initialize Guard
        guard = CORTALicenseGuard(
            public_key_pem_or_path=pub_path,
            codebase_root_dir=tmp_dir,
            manifest_path=mani_path,
            license_path=lic_path,
            lockout_file_path=lockout_path,
            auto_lockout_on_tamper=True,
        )

        @require_feature("corta_core")
        def execute_navigation():
            return "NAVIGATION_ONLINE"

        @require_feature("unlicensed_satellite_relay")
        def execute_satellite_comms():
            return "SATELLITE_ONLINE"

        # Allowed feature executes
        assert execute_navigation() == "NAVIGATION_ONLINE"

        # Unlicensed feature raises LicenseInvalidError
        with pytest.raises(CruxxLicenseInvalidError):
            execute_satellite_comms()

        # NOW INJECT CODE TAMPERING into code_file
        with open(code_file, "a") as f:
            f.write("# unauthorized backdoor injected\n")

        # Next call triggers INSTANT LOCKOUT and raises CruxxTamperLockoutError
        with pytest.raises(CruxxTamperLockoutError):
            execute_navigation()

        # System remains locked out on subsequent calls
        with pytest.raises(CruxxTamperLockoutError):
            execute_navigation()