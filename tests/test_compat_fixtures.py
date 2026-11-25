import copy
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

    def test_schema_compat_detector_pattern_properties(self):
        old = {
            "type": "object",
            "patternProperties": {
                "^[A-Za-z_][A-Za-z0-9_]*$": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "string"},
                        "mode": {"type": "string", "enum": ["a", "b"]},
                    },
                }
            },
        }
        additive = {
            "type": "object",
            "patternProperties": {
                "^[A-Za-z_][A-Za-z0-9_]*$": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "string"},
                        "mode": {"type": "string", "enum": ["a", "b", "c"]},
                        "note": {"type": "string"},
                    },
                },
                "^X_[A-Z0-9_]+$": {"type": "string"},
            },
        }
        self.assertEqual(check_schema_compat.find_breaking_changes(old, additive), [])

        removed_pattern = {"type": "object", "patternProperties": {}}
        errs_removed = check_schema_compat.find_breaking_changes(old, removed_pattern)
        self.assertTrue(any("pattern property removed" in e for e in errs_removed), errs_removed)

        narrowed_sub = {
            "type": "object",
            "patternProperties": {
                "^[A-Za-z_][A-Za-z0-9_]*$": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "integer"},
                        "mode": {"type": "string", "enum": ["a"]},
                    },
                }
            },
        }
        errs_narrowed = check_schema_compat.find_breaking_changes(old, narrowed_sub)
        self.assertTrue(any("allowed type(s) removed" in e for e in errs_narrowed), errs_narrowed)
        self.assertTrue(any("enum value(s) removed" in e for e in errs_narrowed), errs_narrowed)

    def test_schema_compat_detector_oneof_and_anyof(self):
        for comb in ("oneOf", "anyOf"):
            old = {
                comb: [
                    {"type": "string"},
                    {
                        "type": "object",
                        "properties": {
                            "value": {"type": "string"},
                            "valueEnv": {"type": "string"},
                        },
                    },
                ]
            }
            reordered_and_added = {
                comb: [
                    {
                        "type": "object",
                        "properties": {
                            "value": {"type": "string"},
                            "valueEnv": {"type": "string"},
                            "valueVault": {"type": "string"},
                        },
                    },
                    {"type": "string"},
                    {"type": "integer"},
                ]
            }
            self.assertEqual(check_schema_compat.find_breaking_changes(old, reordered_and_added), [])

            reduced_count = {comb: [{"type": "string"}]}
            errs_reduced = check_schema_compat.find_breaking_changes(old, reduced_count)
            self.assertTrue(any("branch count reduced" in e for e in errs_reduced), errs_reduced)

            narrowed_branch = {
                comb: [
                    {"type": "string"},
                    {
                        "type": "object",
                        "properties": {
                            "value": {"type": "string"},
                        },
                    },
                ]
            }
            errs_narrowed = check_schema_compat.find_breaking_changes(old, narrowed_branch)
            self.assertTrue(any("property removed" in e for e in errs_narrowed), errs_narrowed)

            replaced_with_narrow_type = {"type": "string"}
            errs_removed_comb = check_schema_compat.find_breaking_changes(old, replaced_with_narrow_type)
            self.assertTrue(any("allowed type(s) removed" in e for e in errs_removed_comb), errs_removed_comb)

            replaced_with_unconstrained = {}
            self.assertEqual(check_schema_compat.find_breaking_changes(old, replaced_with_unconstrained), [])

    def test_schema_compat_detector_numeric_bounds(self):
        old = {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "unbounded": {"type": "integer"},
                "draft4Bool": {"type": "number", "minimum": 0, "exclusiveMinimum": False},
            },
        }
        relaxed = {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "minimum": 0, "maximum": 65536},
                "unbounded": {"type": "integer"},
                "draft4Bool": {"type": "number", "minimum": 0, "exclusiveMinimum": True},
            },
        }
        self.assertEqual(check_schema_compat.find_breaking_changes(old, relaxed), [])

        tightened = {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "minimum": 1024, "maximum": 49151},
                "unbounded": {"type": "integer", "minimum": 1, "maximum": 100},
                "draft4Bool": {"type": "number", "minimum": 0},
            },
        }
        errs = check_schema_compat.find_breaking_changes(old, tightened)
        self.assertTrue(any("minimum raised" in e for e in errs), errs)
        self.assertTrue(any("maximum lowered" in e for e in errs), errs)
        self.assertTrue(any("minimum constraint added" in e for e in errs), errs)
        self.assertTrue(any("maximum constraint added" in e for e in errs), errs)

    def test_schema_compat_detector_allows_additional_properties_false(self):
        old = {
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {"a": {"type": "string"}},
                }
            },
        }
        new = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "nested": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"a": {"type": "string"}},
                }
            },
        }
        self.assertEqual(check_schema_compat.find_breaking_changes(old, new), [])

    @unittest.skipIf(jsonschema is None, "jsonschema package not installed")
    def test_box_schema_rejects_unknown_keys_and_validates_presets(self):
        def merge_box_config(base, override):
            merged = copy.deepcopy(base)
            for key, val in override.items():
                if isinstance(merged.get(key), dict) and isinstance(val, dict):
                    merged[key] = merge_box_config(merged[key], val)
                else:
                    merged[key] = copy.deepcopy(val)
            return merged

        with open(os.path.join(REPO_ROOT, "box.schema.json"), encoding="utf-8") as f:
            box_schema = json.load(f)
        with open(os.path.join(REPO_ROOT, "box.json"), encoding="utf-8") as f:
            base_box = json.load(f)

        jsonschema.validate(instance=base_box, schema=box_schema)

        preset_paths = sorted(glob.glob(os.path.join(REPO_ROOT, "examples", "presets", "*.local.json")))
        self.assertTrue(preset_paths, "Expected at least one preset under examples/presets/*.local.json")
        for preset_path in preset_paths:
            with open(preset_path, encoding="utf-8") as f:
                preset_override = json.load(f)
            merged = merge_box_config(base_box, preset_override)
            jsonschema.validate(instance=merged, schema=box_schema)

        mutations = [
            ("root", lambda d: d.__setitem__("unknownRoot", True)),
            ("agentUser", lambda d: d["agentUser"].__setitem__("shell", "/bin/bash")),
            ("image", lambda d: d["image"].__setitem__("tag", "latest")),
            ("sharedFolders[0]", lambda d: d.__setitem__("sharedFolders", [{"name": "docs", "windowsPath": "C:\\docs", "mode": "ro", "extra": 1}])),
            ("network", lambda d: d["network"].__setitem__("allowLan", False)),
            ("network.allowedHostPorts[0]", lambda d: d["network"].__setitem__("allowedHostPorts", [{"port": 8080, "protocol": "tcp", "note": "x"}])),
            ("docker", lambda d: d["docker"].__setitem__("allowPrivileged", True)),
            ("docker.defaultLimits", lambda d: d["docker"].__setitem__("defaultLimits", {"memoryBytes": 4194304, "extra": 1})),
            ("docker.maxLimits", lambda d: d["docker"].__setitem__("maxLimits", {"pidsLimit": 10, "extra": 1})),
            ("packages", lambda d: d["packages"].__setitem__("installDocker", True)),
        ]
        for label, mutate in mutations:
            candidate = copy.deepcopy(base_box)
            mutate(candidate)
            with self.assertRaises(jsonschema.ValidationError, msg=f"Expected unknown key rejection in {label}"):
                jsonschema.validate(instance=candidate, schema=box_schema)

    def test_schema_compat_detector_enum_const_combinator_bounds_and_strings(self):
        # Added enum / const narrowing
        self.assertTrue(
            any(
                "enum constraint added" in e
                for e in check_schema_compat.find_breaking_changes(
                    {"type": "string"}, {"enum": ["only-this"]}
                )
            )
        )
        self.assertTrue(
            any(
                "enum constraint added" in e
                for e in check_schema_compat.find_breaking_changes(
                    {"oneOf": [{"type": "string"}, {"type": "integer"}]},
                    {"enum": ["only-this"]},
                )
            )
        )
        self.assertEqual(
            check_schema_compat.find_breaking_changes(
                {"const": "a"}, {"enum": ["a", "b"]}
            ),
            [],
        )
        self.assertTrue(
            any(
                "const constraint added" in e
                for e in check_schema_compat.find_breaking_changes(
                    {"type": "string"}, {"const": "only"}
                )
            )
        )
        self.assertTrue(
            any(
                "const changed" in e
                for e in check_schema_compat.find_breaking_changes(
                    {"const": "a"}, {"const": "b"}
                )
            )
        )

        # anyOf -> oneOf narrowing vs oneOf -> anyOf relaxation
        errs_overlap = check_schema_compat.find_breaking_changes(
            {"anyOf": [{"type": "number"}, {"type": "integer"}]},
            {"oneOf": [{"type": "number"}, {"type": "integer"}]},
        )
        self.assertTrue(any("replaced by oneOf" in e for e in errs_overlap), errs_overlap)

        self.assertEqual(
            check_schema_compat.find_breaking_changes(
                {"anyOf": [{"type": "string"}, {"type": "integer"}]},
                {"oneOf": [{"type": "string"}, {"type": "integer"}]},
            ),
            [],
        )
        self.assertEqual(
            check_schema_compat.find_breaking_changes(
                {"oneOf": [{"type": "number"}, {"type": "integer"}]},
                {"anyOf": [{"type": "number"}, {"type": "integer"}]},
            ),
            [],
        )

        # exclusiveMinimum -> minimum / exclusiveMaximum -> maximum relaxation vs tightening
        self.assertEqual(
            check_schema_compat.find_breaking_changes(
                {"type": "number", "exclusiveMinimum": 5},
                {"type": "number", "minimum": 5},
            ),
            [],
        )
        self.assertTrue(
            check_schema_compat.find_breaking_changes(
                {"type": "number", "exclusiveMinimum": 5},
                {"type": "number", "minimum": 6},
            )
        )
        self.assertTrue(
            check_schema_compat.find_breaking_changes(
                {"type": "number", "minimum": 5},
                {"type": "number", "exclusiveMinimum": 5},
            )
        )
        self.assertEqual(
            check_schema_compat.find_breaking_changes(
                {"type": "number", "exclusiveMaximum": 10},
                {"type": "number", "maximum": 10},
            ),
            [],
        )
        self.assertTrue(
            check_schema_compat.find_breaking_changes(
                {"type": "number", "exclusiveMaximum": 10},
                {"type": "number", "maximum": 9},
            )
        )
        self.assertTrue(
            check_schema_compat.find_breaking_changes(
                {"type": "number", "maximum": 10},
                {"type": "number", "exclusiveMaximum": 10},
            )
        )

        # minLength / maxLength / pattern
        self.assertTrue(
            any(
                "minLength constraint added" in e
                for e in check_schema_compat.find_breaking_changes(
                    {"type": "string"}, {"type": "string", "minLength": 3}
                )
            )
        )
        self.assertTrue(
            any(
                "minLength raised" in e
                for e in check_schema_compat.find_breaking_changes(
                    {"type": "string", "minLength": 1}, {"type": "string", "minLength": 5}
                )
            )
        )
        self.assertEqual(
            check_schema_compat.find_breaking_changes(
                {"type": "string", "minLength": 5}, {"type": "string", "minLength": 2}
            ),
            [],
        )
        self.assertTrue(
            any(
                "maxLength constraint added" in e
                for e in check_schema_compat.find_breaking_changes(
                    {"type": "string"}, {"type": "string", "maxLength": 10}
                )
            )
        )
        self.assertTrue(
            any(
                "maxLength lowered" in e
                for e in check_schema_compat.find_breaking_changes(
                    {"type": "string", "maxLength": 10}, {"type": "string", "maxLength": 5}
                )
            )
        )
        self.assertEqual(
            check_schema_compat.find_breaking_changes(
                {"type": "string", "maxLength": 5}, {"type": "string", "maxLength": 10}
            ),
            [],
        )
        self.assertTrue(
            any(
                "pattern constraint added" in e
                for e in check_schema_compat.find_breaking_changes(
                    {"type": "string"}, {"type": "string", "pattern": "^[a-z]+$"}
                )
            )
        )
        self.assertTrue(
            any(
                "pattern changed" in e
                for e in check_schema_compat.find_breaking_changes(
                    {"type": "string", "pattern": "^[a-z]+$"},
                    {"type": "string", "pattern": "^[0-9]+$"},
                )
            )
        )
        self.assertEqual(
            check_schema_compat.find_breaking_changes(
                {"type": "string", "pattern": "^[a-z]+$"}, {"type": "string"}
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
