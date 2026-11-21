# Agentic Development Workflow

All autonomous and human-assisted agent contributions to this repository must follow this workflow:

## 1. GitHub Issue Required
- **Every contribution must be based on a GitHub issue.**
- Do not start implementation or propose changes without an associated GitHub issue describing the problem, motivation, and acceptance criteria.

## 2. Use Git Worktrees by Default
- **Agents must default to solving issues in a dedicated `git worktree` instead of the primary cloned project directory.**
- Do not switch branches, modify files, or stage changes in the primary cloned repository unless explicitly instructed by the user. This avoids branch collisions and dirty working tree conflicts when multiple agents or developers work in parallel.
- Fetch the latest `origin/main` and create an isolated worktree on a new branch following the naming convention below:

```bash
git fetch origin
git worktree add -b <context>/<issue_number>_<short_description> <worktree_path> origin/main
```

- Perform all implementation, verification, commits, and pushes inside `<worktree_path>`.
- Clean up the worktree once the branch is pushed and the PR is created (or merged) using `git worktree remove <worktree_path>` so stale worktrees do not accumulate.

## 3. Branch Naming Convention
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

## 4. Pull Request & Manual Approval
- **All changes must be merged into `main` via a Pull Request (PR)** for review and **manual approval**.
- Never push directly to `main` or bypass PR review.
- Every PR description **must link to its corresponding GitHub issue** (e.g., `Closes #<issue_number>` or `Fixes #<issue_number>`).
