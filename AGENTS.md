# AGENTS.md

Canonical conventions for working in this repository. This is the single source
of truth for how work is done here; other documents link to this file rather
than restating its contents. It applies to every contributor — human or
automated.

## Project

`@govuk-one-login/mobile-wallet-mdoc-validator` is a published npm package: a
TypeScript library that validates mdoc (ISO/IEC 18013-5) credentials for use
with GOV.UK Wallet. The public entry point is `validateMdoc(credential: string):
Promise<void>` (exported from `src/index.ts`), which resolves when a credential
is valid and throws an `MdocValidationError` when it is not.

## Commands that matter

| Command | What it does |
| --- | --- |
| `nvm use` + `npm install` | Select the pinned Node version (`.nvmrc`) and install dependencies. Use `npm ci` for a clean, lockfile-exact install. |
| `npm run format` | Format the whole repo with Prettier (`prettier --write .`). |
| `npm run build` | Build the dual ESM/CJS bundle with tsdown. |
| `npm test` | Run the Jest suite with coverage under a fixed clock (`TZ=UTC jest --coverage`). |
| `npm run verify` | The single verification gate. Runs typecheck → lint → format check → build → test, mirroring CI (`.github/workflows/validate.yaml`). |

`npm run verify` is the one command to run before considering work done. It
chains `npm run typecheck && npm run lint && npm run format:check && npm run
build && npm test`. If `verify` passes, the CI `validate` job will pass.

## Development workflow

- **TDD is mandatory.** Write tests before the implementation. Work in small,
  independently testable and committable phases.
- **Run the full suite once at the end of a cycle**, not repeatedly during
  inner-loop work. Use focused test runs while iterating; finish with
  `npm run verify`.
- **Never commit on a contributor's behalf.** Leave the work committable and
  propose a Conventional Commit message for the human to run. Do not create
  commits automatically.
- **Prefer self-documenting code** over verbose comments. Reserve comments for
  spec rationale and non-obvious decisions (see the existing comments in
  `src/schemas` and `src/issuerAuth.ts` for the house style).
- **Comply with lint and format.** Code must pass ESLint and Prettier; the
  pre-commit hooks enforce this and will block a commit otherwise.

## Commit and hook conventions

- **Conventional Commits are required.** Commit messages are validated by a
  `commit-msg` hook (`conventional-pre-commit`). Non-conforming messages are
  rejected. Commit types drive automated versioning at release time — see
  `docs/release.md`.
- **Hooks run per git stage** (`.pre-commit-config.yaml`):
  - `commit-msg` stage: `conventional-pre-commit` validates the message.
  - `pre-commit` stage: `eslint`, `prettier`, `typecheck`, plus
    `trailing-whitespace`, `end-of-file-fixer`, and `mixed-line-ending`.
- **Do not bypass hooks** (no `--no-verify`). Install them with:

  ```bash
  pre-commit install --hook-type pre-commit --hook-type commit-msg
  ```

## Coverage expectation

New code should have 100% test coverage

## Spec-driven design decisions

The validator deliberately enforces a narrow, security-conscious subset of
ISO/IEC 18013-5. These decisions are intentional constraints, not omissions,
and each is anchored in source:

- **Digest IDs must be `< 2^31`**, integer and non-negative
  (`src/schemas/issuerSignedItemSchema.ts`). Per the spec, digest IDs are
  smaller than 2^31.
- **Per-item `random` must be at least 16 bytes**
  (`src/schemas/issuerSignedItemSchema.ts`). The spec requires at least 16 bytes
  of randomness per `IssuerSignedItem`.
- **Selective disclosure digest matching** (`validateDigestsMatchMso` in
  `src/issuerAuth.ts`). Every presented item must match an MSO digest; MSO
  digests with no presented item are expected and allowed. Digests are computed
  over the original `IssuerSignedItemBytes` as received (via `saveOriginal` /
  `getEncoded`), never a re-encode, because a re-encode is not guaranteed to be
  byte-identical.
- **Single-certificate `x5chain` only** (`validateUnprotectedHeader` in
  `src/issuerAuth.ts`, COSE header label 33). Multi-certificate chains are
  rejected: the unprotected header must contain exactly one parameter and a
  single parseable X.509 certificate.
- **SHA-256, ES256, and P-256 only.** `digestAlgorithm` must be the literal
  `SHA-256` (`src/schemas/mobileSecurityObjectSchema.ts`); the protected header
  `alg` must be `-7` (ES256) (`src/constants/cose.ts`,
  `validateProtectedHeader`); the device key must be EC2 (kty `2`) on curve
  P-256 (`1`) with exactly the keys `[1, -1, -2, -3]` (`validateDeviceKey`).

## Where to look first

- **[docs/architecture.md](docs/architecture.md)** — the internal components and
  the order `validateMdoc` composes them in.
- **[README.md](README.md)** — how to install and use the library as a consumer.
