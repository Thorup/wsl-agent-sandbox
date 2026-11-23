#!/usr/bin/env python3
"""Detect backward-incompatible JSON Schema changes between two schema versions."""

import json
import sys


def _normalize_types(val):
    if val is None:
        return None
    if isinstance(val, list):
        return set(val)
    return {val}


def find_breaking_changes(old_schema, new_schema, path="$"):
    errors = []
    if not isinstance(old_schema, dict) or not isinstance(new_schema, dict):
        return errors

    # 1. Incompatible type narrowing
    old_types = _normalize_types(old_schema.get("type"))
    new_types = _normalize_types(new_schema.get("type"))
    if old_types is not None and new_types is not None:
        removed_types = old_types - new_types
        if removed_types:
            errors.append(
                f"{path}: allowed type(s) removed: {sorted(removed_types)} (old={sorted(old_types)}, new={sorted(new_types)})"
            )

    # 2. Enum values removed
    if "enum" in old_schema and "enum" in new_schema:
        old_enum = set(old_schema["enum"])
        new_enum = set(new_schema["enum"])
        removed_enum = old_enum - new_enum
        if removed_enum:
            errors.append(f"{path}: enum value(s) removed: {sorted(map(str, removed_enum))}")

    # 3. New required fields added to existing object
    old_req = set(old_schema.get("required", []))
    new_req = set(new_schema.get("required", []))
    added_req = new_req - old_req
    if added_req:
        errors.append(f"{path}: newly required field(s) added: {sorted(added_req)}")

    # 4. Existing properties removed (or recursively broken)
    old_props = old_schema.get("properties", {})
    new_props = new_schema.get("properties", {})
    if isinstance(old_props, dict) and isinstance(new_props, dict):
        for prop, old_sub in old_props.items():
            if prop not in new_props:
                errors.append(f"{path}.properties.{prop}: property removed")
            else:
                errors.extend(find_breaking_changes(old_sub, new_props[prop], f"{path}.properties.{prop}"))

    # 5. Array items schema
    if isinstance(old_schema.get("items"), dict) and isinstance(new_schema.get("items"), dict):
        errors.extend(find_breaking_changes(old_schema["items"], new_schema["items"], f"{path}.items"))

    return errors


def main(argv):
    if len(argv) != 3:
        print("Usage: check_schema_compat.py <old_schema.json> <new_schema.json>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        old_schema = json.load(f)
    with open(argv[2], encoding="utf-8") as f:
        new_schema = json.load(f)
    errors = find_breaking_changes(old_schema, new_schema)
    if errors:
        print("Breaking JSON Schema change(s) detected:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"[PASS] {argv[2]} is backward-compatible with {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
