# Agentic Development Workflow

All autonomous and human-assisted agent contributions to this repository must follow this workflow:

## 1. GitHub Issue Required
- **Every contribution must be based on a GitHub issue.**
- Do not start implementation or propose changes without an associated GitHub issue describing the problem, motivation, and acceptance criteria.

## 2. Branch Naming Convention
- **Every contribution must be developed on a separate branch** created from `main` (never commit directly to `main`).
- Branch names must strictly follow this format:

```text
<context>/<issue_number>_<short_description>
```

Where:
- `<context>` describes the type of change (e.g., `feat`, `bug`, `docs`, `chore`, `refactor`, `test`).
- `<issue_number>` is the corresponding GitHub issue number.
- `<short_description>` is **at most four words** describing the branch, lowercase and separated by underscores (`_`).

### Examples
- `docs/12_port_forward_hardening_guide`
- `feat/25_add_custom_dns_config`
- `bug/7_fix_mirrored_loopback_rule`
- `chore/31_update_ubuntu_base_image`

## 3. Pull Request & Manual Approval
- **All changes must be merged into `main` via a Pull Request (PR)** for review and **manual approval**.
- Never push directly to `main` or bypass PR review.
- Every PR description **must link to its corresponding GitHub issue** (e.g., `Closes #<issue_number>` or `Fixes #<issue_number>`).
