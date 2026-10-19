# Contributing

This guide gets a new contributor set up and pointed at the right documents. It
does **not** restate the project conventions — those live in
[AGENTS.md](AGENTS.md), which is the single source of truth for how work is done
here (for humans and automated contributors alike). When this guide and
AGENTS.md ever disagree, AGENTS.md wins.

## Setup

```bash
nvm use            # select the Node version pinned in .nvmrc (nvm install first if needed)
npm ci             # clean, lockfile-exact dependency install

pip install pre-commit   # or: brew install pre-commit
pre-commit install --hook-type pre-commit --hook-type commit-msg
```

The last two commands install the `pre-commit` tool and wire up the git hooks,
so commit and code conventions are enforced locally before CI runs.

## What the hooks do

The hooks are configured in
[`.pre-commit-config.yaml`](.pre-commit-config.yaml) and run at two git stages:

- **`commit-msg`** — `conventional-pre-commit` validates that your commit
  message is a Conventional Commit. A non-conforming message is rejected.
- **`pre-commit`** — `eslint`, `prettier`, and `typecheck`, plus
  `trailing-whitespace`, `end-of-file-fixer`, and `mixed-line-ending`.

Do not bypass the hooks (no `--no-verify`); CI enforces the same checks and will
fail without them. See AGENTS.md for the full rationale.

## Before you push

Run the single verification gate, which mirrors CI:

```bash
npm run verify
```

It chains typecheck → lint → format check → build → test. If `verify` passes
locally, the CI `validate` job will pass. Run it once before pushing rather than
repeatedly while iterating.

## How we work

The working conventions (TDD in small phases, Conventional Commits, code style)
are in [AGENTS.md](AGENTS.md). The one contribution-specific rule to remember:
**documentation travels with the code.** A behavioural change must update the
docs that describe it, in the same change:

- a **validation rule** change → [docs/validation.md](docs/validation.md);
- a **public API or exported type** change → [README.md](README.md), and
  [docs/architecture.md](docs/architecture.md) if the internal flow changes.

## Where to look next

- [AGENTS.md](AGENTS.md) — canonical conventions (start here).
- [docs/architecture.md](docs/architecture.md) — how `validateMdoc` composes its
  internal components.
- [docs/validation.md](docs/validation.md) — the complete validation rules,
  limits, and error messages.
- [README.md](README.md) — using the library as a consumer.
- [docs/release.md](docs/release.md) — how a merge becomes a published package.
