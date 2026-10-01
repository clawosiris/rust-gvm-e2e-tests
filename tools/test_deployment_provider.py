#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("deployment_provider.py")
SPEC = importlib.util.spec_from_file_location("deployment_provider", MODULE_PATH)
assert SPEC and SPEC.loader
PROVIDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROVIDER
SPEC.loader.exec_module(PROVIDER)


class DeploymentProviderTests(unittest.TestCase):
    def catalog(self):
        return {"schema_version": 1, "features": {"ENABLE_AGENTS": {}}}

    def contract(self):
        return {"schema_version": 1, "deployment_id": "enterprise-ci", "features": {"ENABLE_AGENTS": "required"}, "fixtures": {"agent_endpoint": "required"}, "allow_legacy_fallback": []}

    def test_contract_rejects_unknown_feature_and_requirement(self):
        contract = self.contract(); contract["features"]["FUTURE"] = "required"
        with self.assertRaisesRegex(ValueError, "unmapped"):
            PROVIDER.validate_contract(contract, self.catalog())
        contract = self.contract(); contract["features"]["ENABLE_AGENTS"] = "maybe"
        with self.assertRaisesRegex(ValueError, "invalid requirement"):
            PROVIDER.validate_contract(contract, self.catalog())
        contract = self.contract(); contract["allow_legacy_fallback"] = ["ENABLE_AGENTS"]
        with self.assertRaisesRegex(ValueError, "only for contracted optional"):
            PROVIDER.validate_contract(contract, self.catalog())

    def test_fixture_descriptor_requires_identity_state_and_evidence(self):
        valid = {"schema_version": 1, "deployment_id": "enterprise-ci", "fixtures": {"agent_endpoint": {"state": "ready", "detail": "health endpoint returned ready"}}, "probes": {"jwt-auth": {"state": "unavailable", "detail": "endpoint is not configured"}}}
        PROVIDER.validate_fixture_descriptor(valid, "enterprise-ci")
        valid["fixtures"]["agent_endpoint"]["state"] = "skipped"
        with self.assertRaisesRegex(ValueError, "invalid state"):
            PROVIDER.validate_fixture_descriptor(valid, "enterprise-ci")

    def test_descriptors_reject_unknown_secret_bearing_fields(self):
        contract = self.contract()
        contract["password"] = "must-not-be-uploaded"
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            PROVIDER.validate_contract(contract, self.catalog())

        fixture = {"schema_version": 1, "deployment_id": "enterprise-ci", "fixtures": {}, "token": "must-not-be-uploaded"}
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            PROVIDER.validate_fixture_descriptor(fixture, "enterprise-ci")

        provider = {"schema_version": 1, "deployment_id": "enterprise-ci", "transport": {"kind": "unix", "socket_path": "/run/private/gvmd.sock"}, "runtime_images_path": "/run/private/images.json", "secret": "must-not-be-uploaded"}
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            PROVIDER.validate_external_provider(provider, "enterprise-ci")

    def test_external_provider_is_lifecycle_neutral_and_unix_socket_scoped(self):
        valid = {"schema_version": 1, "deployment_id": "enterprise-ci", "transport": {"kind": "unix", "socket_path": "/run/private/gvmd.sock"}, "runtime_images_path": "/run/private/images.json"}
        PROVIDER.validate_external_provider(valid, "enterprise-ci")
        valid["transport"]["socket_path"] = "../gvmd.sock"
        with self.assertRaisesRegex(ValueError, "absolute normalized"):
            PROVIDER.validate_external_provider(valid, "enterprise-ci")


if __name__ == "__main__":
    unittest.main()
