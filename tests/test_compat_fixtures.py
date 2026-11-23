import glob
import importlib.util
import json
import os
import subprocess
import unittest

try:
    import jsonschema
except ImportError:
    jsonschema = None

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKER_PATH = os.path.join(REPO_ROOT, "scripts", "ci", "check_schema_compat.py")
spec = importlib.util.spec_from_file_location("check_schema_compat", CHECKER_PATH)
check_schema_compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_schema_compat)


class TestCompatFixturesAndSchemaGuard(unittest.TestCase):
    @unittest.skipIf(jsonschema is None, "jsonschema package not installed")
    def test_golden_legacy_fixtures_validate_against_current_schemas(self):
        compat_dir = os.path.join(REPO_ROOT, "tests", "fixtures", "compat")
        box_fixtures = sorted(glob.glob(os.path.join(compat_dir, "box-*.json")))
        secrets_fixtures = sorted(glob.glob(os.path.join(compat_dir, "secrets-*.json")))

        self.assertTrue(box_fixtures, "Expected at least one tests/fixtures/compat/box-*.json fixture")
        self.assertTrue(secrets_fixtures, "Expected at least one tests/fixtures/compat/secrets-*.json fixture")

        with open(os.path.join(REPO_ROOT, "box.schema.json"), encoding="utf-8") as f:
            box_schema = json.load(f)
        with open(os.path.join(REPO_ROOT, "secrets.schema.json"), encoding="utf-8") as f:
            secrets_schema = json.load(f)

        for path in box_fixtures:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            jsonschema.validate(instance=data, schema=box_schema)

        for path in secrets_fixtures:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            jsonschema.validate(instance=data, schema=secrets_schema)

    def test_schema_compat_detector_flags_breaking_and_allows_additive(self):
        old = {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "mode": {"type": "string", "enum": ["ro", "rw"]},
                "count": {"type": ["integer", "string"]},
            },
        }
        additive = {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "mode": {"type": "string", "enum": ["ro", "rw", "auto"]},
                "count": {"type": ["integer", "string"]},
                "newOptional": {"type": "boolean"},
            },
        }
        self.assertEqual(check_schema_compat.find_breaking_changes(old, additive), [])

        breaking = {
            "type": "object",
            "required": ["name", "newReq"],
            "properties": {
                "name": {"type": "string"},
                "mode": {"type": "string", "enum": ["ro"]},
                "count": {"type": "integer"},
                "newReq": {"type": "string"},
            },
        }
        errs = check_schema_compat.find_breaking_changes(old, breaking)
        self.assertTrue(any("newly required" in e for e in errs), errs)
        self.assertTrue(any("enum value(s) removed" in e for e in errs), errs)
        self.assertTrue(any("allowed type(s) removed" in e for e in errs), errs)

        removed_prop = {
            "type": "object",
            "required": ["name"],
            "properties": {"name": {"type": "string"}},
        }
        errs_removed = check_schema_compat.find_breaking_changes(old, removed_prop)
        self.assertTrue(any("property removed" in e for e in errs_removed), errs_removed)

    def test_current_schemas_backward_compatible_with_origin_main(self):
        for schema_name in ("box.schema.json", "secrets.schema.json"):
            proc = subprocess.run(
                ["git", "-C", REPO_ROOT, "show", f"origin/main:{schema_name}"],
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                self.skipTest(f"origin/main:{schema_name} not available in shallow clone")
            old_schema = json.loads(proc.stdout)
            with open(os.path.join(REPO_ROOT, schema_name), encoding="utf-8") as f:
                new_schema = json.load(f)
            errs = check_schema_compat.find_breaking_changes(old_schema, new_schema)
            self.assertEqual(
                errs,
                [],
                f"{schema_name} has backward-incompatible change(s) vs origin/main: {errs}",
            )


if __name__ == "__main__":
    unittest.main()
