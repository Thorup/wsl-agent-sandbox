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


def _is_number(val):
    return isinstance(val, (int, float)) and not isinstance(val, bool)


def _same_json_value(a, b):
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same_json_value(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same_json_value(a[k], b[k]) for k in a)
    return a == b


def _json_primitive_type(val):
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, int):
        return "integer"
    if isinstance(val, float):
        return "number"
    if isinstance(val, str):
        return "string"
    if isinstance(val, list):
        return "array"
    if isinstance(val, dict):
        return "object"
    return "unknown"


def _inferred_types(schema):
    if not isinstance(schema, dict):
        return None
    t = _normalize_types(schema.get("type"))
    if t is not None:
        return t
    if "const" in schema:
        return {_json_primitive_type(schema["const"])}
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return {_json_primitive_type(v) for v in schema["enum"]}
    return None


def _branches_may_overlap(b1, b2):
    if not isinstance(b1, dict) or not isinstance(b2, dict):
        return True
    t1 = _inferred_types(b1)
    t2 = _inferred_types(b2)
    if t1 is not None and t2 is not None:
        t1_exp = set(t1)
        t2_exp = set(t2)
        if "number" in t1_exp:
            t1_exp.add("integer")
        if "number" in t2_exp:
            t2_exp.add("integer")
        if not (t1_exp & t2_exp):
            return False
    vals1 = [b1["const"]] if "const" in b1 else (b1["enum"] if isinstance(b1.get("enum"), list) else None)
    vals2 = [b2["const"]] if "const" in b2 else (b2["enum"] if isinstance(b2.get("enum"), list) else None)
    if vals1 is not None and vals2 is not None:
        if not any(_same_json_value(v1, v2) for v1 in vals1 for v2 in vals2):
            return False
    return True


def _effective_lower_bound(schema):
    candidates = []
    if _is_number(schema.get("minimum")):
        candidates.append(((schema["minimum"], 0), "minimum", schema["minimum"]))
    if _is_number(schema.get("exclusiveMinimum")):
        candidates.append(((schema["exclusiveMinimum"], 1), "exclusiveMinimum", schema["exclusiveMinimum"]))
    return max(candidates, key=lambda item: item[0]) if candidates else None


def _effective_upper_bound(schema):
    candidates = []
    if _is_number(schema.get("maximum")):
        candidates.append(((-schema["maximum"], 0), "maximum", schema["maximum"]))
    if _is_number(schema.get("exclusiveMaximum")):
        candidates.append(((-schema["exclusiveMaximum"], 1), "exclusiveMaximum", schema["exclusiveMaximum"]))
    return max(candidates, key=lambda item: item[0]) if candidates else None


_CONSTRAINING_KEYS = {
    "type",
    "enum",
    "required",
    "properties",
    "patternProperties",
    "items",
    "additionalProperties",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "oneOf",
    "anyOf",
    "allOf",
    "const",
    "pattern",
    "minLength",
    "maxLength",
}


def _match_combinator_branches(old_branches, new_branches, path, comb_key):
    errors = []
    if len(new_branches) < len(old_branches):
        errors.append(
            f"{path}.{comb_key}: branch count reduced ({len(old_branches)} -> {len(new_branches)})"
        )

    # Exact bipartite matching from old branches to compatible new branches
    compat_edges = [
        [
            j
            for j, new_b in enumerate(new_branches)
            if not find_breaking_changes(old_b, new_b, f"{path}.{comb_key}[{i}]")
        ]
        for i, old_b in enumerate(old_branches)
    ]
    match_new = [-1] * len(new_branches)

    def _dfs(u, seen):
        for v in compat_edges[u]:
            if seen[v]:
                continue
            seen[v] = True
            if match_new[v] == -1 or _dfs(match_new[v], seen):
                match_new[v] = u
                return True
        return False

    matched_old = set()
    for i in range(len(old_branches)):
        if _dfs(i, [False] * len(new_branches)):
            matched_old.add(i)

    used_new = {j for j, old_i in enumerate(match_new) if old_i != -1}
    for i, old_b in enumerate(old_branches):
        if i in matched_old:
            continue
        candidate_indices = [j for j in range(len(new_branches)) if j not in used_new]
        if not candidate_indices:
            candidate_indices = list(range(len(new_branches)))
        if not candidate_indices:
            errors.append(f"{path}.{comb_key}[{i}]: compatible branch removed")
            continue

        old_types = _normalize_types(old_b.get("type")) if isinstance(old_b, dict) else None
        best_errs = None
        best_key = None
        for j in candidate_indices:
            new_b = new_branches[j]
            sub_errs = find_breaking_changes(old_b, new_b, f"{path}.{comb_key}[{i}]")
            if not sub_errs:
                sub_errs = [f"{path}.{comb_key}[{i}]: compatible branch removed or narrowed"]
            new_types = _normalize_types(new_b.get("type")) if isinstance(new_b, dict) else None
            type_mismatch = 0 if (old_types is not None and old_types == new_types) else 1
            rank = (type_mismatch, len(sub_errs), j)
            if best_key is None or rank < best_key:
                best_key = rank
                best_errs = sub_errs
        errors.extend(best_errs)

    return errors


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

    # 2. Enum / const constraints
    if "enum" in new_schema:
        new_enum = new_schema["enum"]
        if "enum" in old_schema:
            removed_enum = [
                v for v in old_schema["enum"] if not any(_same_json_value(v, nv) for nv in new_enum)
            ]
            if removed_enum:
                errors.append(f"{path}: enum value(s) removed: {sorted(map(str, removed_enum))}")
        elif "const" in old_schema:
            if not any(_same_json_value(old_schema["const"], nv) for nv in new_enum):
                errors.append(f"{path}: enum constraint excludes previous const ({old_schema['const']!r})")
        else:
            errors.append(f"{path}: enum constraint added ({new_enum})")

    if "const" in new_schema:
        new_const = new_schema["const"]
        if "const" not in old_schema:
            old_enum = old_schema.get("enum")
            if not (isinstance(old_enum, list) and len(old_enum) == 1 and _same_json_value(old_enum[0], new_const)):
                errors.append(f"{path}: const constraint added ({new_const!r})")
        elif not _same_json_value(old_schema["const"], new_const):
            errors.append(f"{path}: const changed ({old_schema['const']!r} -> {new_const!r})")

    # 3. Numeric bounds tightened (minimum / exclusiveMinimum raised, maximum / exclusiveMaximum lowered)
    old_lb = _effective_lower_bound(old_schema)
    new_lb = _effective_lower_bound(new_schema)
    if new_lb is not None:
        new_rank, new_key, new_val = new_lb
        if old_lb is None:
            errors.append(f"{path}: {new_key} constraint added ({new_val})")
        else:
            old_rank, old_key, old_val = old_lb
            if new_rank > old_rank:
                if new_key == old_key:
                    errors.append(f"{path}: {new_key} raised ({old_val} -> {new_val})")
                else:
                    errors.append(
                        f"{path}: {new_key} tightened beyond previous {old_key} ({old_val} -> {new_val})"
                    )

    old_ub = _effective_upper_bound(old_schema)
    new_ub = _effective_upper_bound(new_schema)
    if new_ub is not None:
        new_rank, new_key, new_val = new_ub
        if old_ub is None:
            errors.append(f"{path}: {new_key} constraint added ({new_val})")
        else:
            old_rank, old_key, old_val = old_ub
            if new_rank > old_rank:
                if new_key == old_key:
                    errors.append(f"{path}: {new_key} lowered ({old_val} -> {new_val})")
                else:
                    errors.append(
                        f"{path}: {new_key} tightened beyond previous {old_key} ({old_val} -> {new_val})"
                    )

    # 3b. String constraints (minLength / maxLength / pattern)
    old_min_len = old_schema.get("minLength")
    new_min_len = new_schema.get("minLength")
    if _is_number(new_min_len):
        if not _is_number(old_min_len):
            errors.append(f"{path}: minLength constraint added ({new_min_len})")
        elif new_min_len > old_min_len:
            errors.append(f"{path}: minLength raised ({old_min_len} -> {new_min_len})")

    old_max_len = old_schema.get("maxLength")
    new_max_len = new_schema.get("maxLength")
    if _is_number(new_max_len):
        if not _is_number(old_max_len):
            errors.append(f"{path}: maxLength constraint added ({new_max_len})")
        elif new_max_len < old_max_len:
            errors.append(f"{path}: maxLength lowered ({old_max_len} -> {new_max_len})")

    new_pattern = new_schema.get("pattern")
    if isinstance(new_pattern, str):
        old_pattern = old_schema.get("pattern")
        if old_pattern is None:
            errors.append(f"{path}: pattern constraint added ({new_pattern!r})")
        elif old_pattern != new_pattern:
            errors.append(f"{path}: pattern changed ({old_pattern!r} -> {new_pattern!r})")

    # 4. New required fields added to existing object
    old_req = set(old_schema.get("required", []))
    new_req = set(new_schema.get("required", []))
    added_req = new_req - old_req
    if added_req:
        errors.append(f"{path}: newly required field(s) added: {sorted(added_req)}")

    # 5. Existing properties removed (or recursively broken)
    old_props = old_schema.get("properties", {})
    new_props = new_schema.get("properties", {})
    if isinstance(old_props, dict) and isinstance(new_props, dict):
        for prop, old_sub in old_props.items():
            if prop not in new_props:
                errors.append(f"{path}.properties.{prop}: property removed")
            else:
                errors.extend(find_breaking_changes(old_sub, new_props[prop], f"{path}.properties.{prop}"))

    # 6. Existing patternProperties removed (or recursively broken)
    old_pat_props = old_schema.get("patternProperties")
    new_pat_props = new_schema.get("patternProperties")
    if isinstance(old_pat_props, dict):
        if not isinstance(new_pat_props, dict):
            new_pat_props = {}
        for pattern, old_sub in old_pat_props.items():
            if pattern not in new_pat_props:
                errors.append(f"{path}.patternProperties[{pattern!r}]: pattern property removed")
            else:
                errors.extend(
                    find_breaking_changes(
                        old_sub,
                        new_pat_props[pattern],
                        f"{path}.patternProperties[{pattern!r}]",
                    )
                )

    # 7. Array items schema
    if isinstance(old_schema.get("items"), dict) and isinstance(new_schema.get("items"), dict):
        errors.extend(find_breaking_changes(old_schema["items"], new_schema["items"], f"{path}.items"))

    # 8. oneOf / anyOf combinators (allow adding/reordering branches, flag removed/narrowed branches)
    for comb_key in ("oneOf", "anyOf"):
        old_branches = old_schema.get(comb_key)
        if not isinstance(old_branches, list) or not old_branches:
            continue
        new_branches = new_schema.get(comb_key)
        if isinstance(new_branches, list):
            errors.extend(_match_combinator_branches(old_branches, new_branches, path, comb_key))
        elif comb_key == "oneOf" and isinstance(new_schema.get("anyOf"), list):
            errors.extend(_match_combinator_branches(old_branches, new_schema["anyOf"], path, comb_key))
        elif comb_key == "anyOf" and isinstance(new_schema.get("oneOf"), list):
            new_one_of = new_schema["oneOf"]
            errors.extend(_match_combinator_branches(old_branches, new_one_of, path, comb_key))
            has_overlap = any(
                _branches_may_overlap(new_one_of[i], new_one_of[j])
                for i in range(len(new_one_of))
                for j in range(i + 1, len(new_one_of))
            )
            if has_overlap:
                errors.append(
                    f"{path}.anyOf: anyOf replaced by oneOf with potentially overlapping branches"
                )
        elif any(k in new_schema for k in _CONSTRAINING_KEYS):
            for idx, old_branch in enumerate(old_branches):
                errors.extend(
                    find_breaking_changes(old_branch, new_schema, f"{path}.{comb_key}[{idx}]")
                )

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
