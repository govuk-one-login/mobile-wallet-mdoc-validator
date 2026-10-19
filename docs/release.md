# Release process

Releases are automated and commit-driven: you write Conventional Commit
messages, and a merge to `main` is turned into a published npm package without a
manual version or publish step. This document covers the concepts behind the
pipeline and what each part is responsible for, not the workflow YAML line by
line.

The Conventional Commits requirement and the commit-message hook that enforces
it are defined in [AGENTS.md](../AGENTS.md); the mapping from commit type to
version bump is in [Version selection from commits](#version-selection-from-commits)
below. For how to consume the published package, see [README.md](../README.md).

## Version selection from commits

The version is a function of the commits since the last release, not a manual
decision. Conventional Commit types carry the intent:

- `fix:` describes a backwards-compatible bug fix → **patch**.
- `feat:` describes a backwards-compatible feature → **minor**.
- a breaking change (`!` or a `BREAKING CHANGE:` footer) → **major**.
- everything else (`docs:`, `chore:`, `test:`, `refactor:`, …) → **no release**.

Because the commit message is the release input, it must state the change
accurately. If the commits since the last tag contain nothing releasable, the
outcome is _no release_, not a failure.

**cocogitto** (`cog.toml`) reads those commits and computes the bump. Its
configuration: tags are prefixed `v`, no changelog file is kept
(`disable_changelog`), merge commits are ignored, and the computed version is
written into `package.json` as part of the bump so the manifest and the tag
always agree.

## Pipeline stages and approval gate

The pipeline is split into two workflows, divided by the point a version becomes
real:

1. **Decide and tag** (`release.yaml`, triggered by merge to `main`). Decides
   _whether_ to release and, if so, creates the version bump and the `vX.Y.Z`
   tag. Fully automated.
2. **Publish** (`publish.yml`, triggered by the new tag). Re-runs build and test
   (on Node 24, pinned explicitly rather than from `.nvmrc`), then publishes to
   npm and creates a GitHub release.

The boundary between them is a git tag, so publishing reacts to a tag existing
rather than running inside the merge.

There is exactly **one** human checkpoint: the publish stage runs inside a
protected GitHub environment (`npm-publish`) whose required reviewers must
approve before anything reaches npm. Everything up to and including tagging is
automatic; publishing requires approval.

## Trust and identity

Two parts encode trust decisions:

- **Pushing past branch protection.** `main` is protected, so the automated
  bump commit and tag are pushed by a dedicated GitHub App identity, not the
  default workflow token. The AWS OIDC + Secrets Manager hop exists only to
  fetch that App's private key on demand instead of storing it in the repo.
- **Publishing without a long-lived token.** Publishing uses npm **OIDC trusted
  publishing**: npm trusts the workflow's short-lived OIDC identity, so no
  static publish token is stored. Build **provenance** is emitted automatically
  for a public repository publishing a public package via OIDC.

## Guards that keep the loop stable

A commit-driven release that pushes its own commit could trigger itself. Two
guards prevent that and keep the pipeline idempotent:

- **Release-loop guard.** The bump commit is a `chore(version):` commit, and the
  release stage skips commits whose message starts with that prefix. So pushing
  the bump does not kick off another release.
- **Tag/manifest consistency check.** Before publishing, the publish stage
  verifies the tag (`vX.Y.Z`) matches the `version` in `package.json` and fails
  if they diverge — a release can only publish the version it claims to be.
- **Idempotent GitHub release.** The GitHub release is only created if one does
  not already exist for the tag, so re-running publish is safe.

## Quality gates

The release stage proceeds only once three independent checks pass: code
quality/security analysis (SonarQube), the full verification build
(`validate.yaml` — the same typecheck → lint → format check → build → test gate
run locally as `npm run verify`), and a Conventional Commits check. These are
the same standards enforced on every PR; the release stage will not tag anything
that would not have passed them.

The publish stage then re-runs `npm run build` and `npm test` against the tagged
commit before publishing, so the artifact is verified again at publish time, not
only at merge time.

## How to cut a release

1. Land changes on `main` via PRs using accurate Conventional Commit messages —
   the message is what determines the bump.
2. On merge, the release stage runs automatically. If the commits warrant it, it
   creates the bump and the `vX.Y.Z` tag; if not, nothing is released.
3. The tag starts the publish stage, which pauses on the `npm-publish`
   environment. **Approve it** to publish.
4. Confirm the new version on npm and the generated GitHub release.

## One-time, out-of-repo setup

The pipeline depends on infrastructure that lives outside the repository. It
will not work until all of the following exist:

- a **GitHub App** permitted to push to `main` past branch protection, acting as
  the release bot;
- an **AWS Secrets Manager** entry holding that App's credentials
  (`ci/release_action/mdoc_release_app_mdoc_validator`);
- an **AWS IAM role** assumable via GitHub OIDC (referenced by
  `vars.AWS_RELEASE_ROLE_ARN`, with `vars.AWS_REGION`) with read access to that
  secret;
- the protected **`npm-publish` GitHub environment** with required reviewers —
  the single approval gate;
- **npm trusted-publisher registration** for the package, enabling OIDC
  publishing with automatic provenance.

These dependencies are external to the repository: a copy or fork without them
will tag but never publish.
