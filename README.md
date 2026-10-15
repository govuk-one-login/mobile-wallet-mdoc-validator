# Mobile Wallet mdoc Validator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`@govuk-one-login/mobile-wallet-mdoc-validator` is a TypeScript library that
validates mdoc (ISO/IEC 18013-5) credentials for use with GOV.UK Wallet. The
public entry point is `validateMdoc(credential: string): Promise<void>`, which
resolves when a credential is valid and throws an `MdocValidationError` when it
is not.

## What it does

Given a base64url-encoded mdoc credential, `validateMdoc`:

- decodes the credential (base64url, then CBOR);
- parses and schema-validates the `IssuerSigned` structure;
- checks the namespaces (duplicate digest IDs and element identifiers,
  bounds, and Latin-1 restrictions on keys and strings);
- validates the issuer authentication (`COSE_Sign1`): protected header,
  signing certificate, signature, Mobile Security Object (MSO), validity
  info, selective-disclosure digest matching, and the device key.

## What it does not do

The validator enforces a deliberately narrow, security-conscious subset of
ISO/IEC 18013-5. The following are intentional constraints, not omissions:

- **Single-certificate `x5chain` only.** The unprotected header must contain
  exactly one parameter — a single parseable X.509 certificate (COSE header
  label 33). Multi-certificate chains (e.g. with an intermediate) are
  rejected.
- **ES256 / SHA-256 / P-256 only.** The protected header `alg` must be `-7`
  (ES256); the MSO `digestAlgorithm` must be the literal `SHA-256`; the device
  key must be EC2 (kty `2`) on curve P-256 (`1`).

Responsibilities the validator does **not** take on, and which remain with the
caller:

- It does not establish trust in the signing certificate. It verifies the
  issuer signature against the public key in the embedded certificate, but it
  does not check that certificate against a trust anchor, PKI chain, or
  revocation status.
- It does not perform device-side (holder binding) verification; it validates
  only the issuer-signed structure (`IssuerSigned`), not a full
  `DeviceResponse`.
- It does not interpret or return claim values; it validates structure and
  integrity and either resolves or throws.

See [docs/validation.md](docs/validation.md) for the complete rule-by-rule
reference, including every limit and exact error message.

## Prerequisites

- [Node.js](https://nodejs.org/en) v22 or later (`engines.node >= 22`).
- The package is published as `@govuk-one-login/mobile-wallet-mdoc-validator`
  and ships dual ESM/CJS builds with TypeScript types.

## Install

```bash
npm install @govuk-one-login/mobile-wallet-mdoc-validator
```

## Quick start

```ts
import {
  validateMdoc,
  MdocValidationError,
} from "@govuk-one-login/mobile-wallet-mdoc-validator";

// A base64url-encoded mdoc credential (IssuerSigned), as received by the caller.
const credential: string = "<base64url-encoded-credential>";

try {
  await validateMdoc(credential);
  // Resolved: the credential is valid.
  console.log("Credential is valid");
} catch (error) {
  if (error instanceof MdocValidationError) {
    // Rejected: the credential is invalid.
    console.error(`Invalid credential [${error.code}]: ${error.message}`);
  } else {
    throw error;
  }
}
```

CommonJS consumers can `require` the package instead:

```cjs
const {
  validateMdoc,
  MdocValidationError,
} = require("@govuk-one-login/mobile-wallet-mdoc-validator");
```

## Input model

`validateMdoc` takes a single argument: a **base64url-encoded string** that
decodes (via CBOR) to an `IssuerSigned` structure, which has two top-level
properties:

- `nameSpaces` — a map from namespace identifier to a non-empty array of
  encoded `IssuerSignedItem` entries (each item carries a `digestID`,
  `elementIdentifier`, `elementValue`, and `random`).
- `issuerAuth` — a `COSE_Sign1` tuple of `[protected header, unprotected
header, payload, signature]`, where the payload is the Mobile Security
  Object (MSO).

The exact limits, bounds, and structural rules applied to each field are
documented in [docs/validation.md](docs/validation.md). For the order in which
the components run and the data passed between them, see
[docs/architecture.md](docs/architecture.md).

## Behavioural contract

- **Resolves on valid, throws on invalid.** `validateMdoc` returns
  `Promise<void>`. It resolves with no value when the credential is valid and
  rejects with an `MdocValidationError` when it is not. It does **not** return
  a boolean.
- **Time is captured at call time.** The current time used for validity-info
  checks (`signed`, `validFrom`, `validUntil`, `expectedUpdate`) is read as
  `new Date()` at the moment of the call. The same credential can be valid at
  one time and invalid later.
- **Selective disclosure is supported.** Every presented item must match an
  MSO digest, but MSO digests with no presented item are expected and allowed.

## Error handling

Validation failures throw an `MdocValidationError`, an `Error` subclass with a
string `code` identifying the category of failure:

```ts
import {
  validateMdoc,
  MdocValidationError,
} from "@govuk-one-login/mobile-wallet-mdoc-validator";

try {
  await validateMdoc(credential);
} catch (error) {
  if (error instanceof MdocValidationError) {
    switch (error.code) {
      case "INVALID_SIGNATURE":
        // handle signature failure
        break;
      case "INVALID_VALIDITY_INFO":
        // handle expired / not-yet-valid credential
        break;
      default:
        // handle other validation failures
        break;
    }
    console.error(error.code, error.message);
  }
}
```

Error codes include:

| Code                          | Raised when                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------ |
| `INVALID_BASE64URL`           | The credential string is not valid base64url.                                  |
| `INVALID_CBOR`                | The decoded bytes are not valid CBOR.                                          |
| `INVALID_SCHEMA`              | A decoded structure does not comply with its schema.                           |
| `INVALID_DIGEST_IDS`          | A namespace contains a duplicate digest ID.                                    |
| `INVALID_ELEMENT_IDENTIFIERS` | A namespace contains a duplicate element identifier.                           |
| `INVALID_PROTECTED_HEADER`    | The COSE protected header is missing, malformed, or not ES256.                 |
| `INVALID_UNPROTECTED_HEADER`  | The COSE unprotected header / `x5chain` certificate is missing or unparseable. |
| `INVALID_SIGNATURE`           | The issuer signature does not verify.                                          |
| `INVALID_VALIDITY_INFO`       | One or more validity-info dates fail the temporal rules.                       |
| `INVALID_DIGESTS`             | A presented item does not match an MSO digest.                                 |
| `INVALID_DEVICE_KEY`          | The device key is not a valid EC2 / P-256 key with the required parameters.    |
| `VALIDATION_FAILED`           | Default code for an uncategorised validation failure.                          |

The message of a schema failure (`INVALID_SCHEMA`) lists each offending field
using `path/to/field: message` notation (or `root` for the top level), joined
by `"; "`. See [docs/validation.md](docs/validation.md) for the exact messages
per rule.

## Documentation

- [AGENTS.md](AGENTS.md) — canonical conventions for working in this
  repository (the single source of truth for how work is done here).
- [docs/architecture.md](docs/architecture.md) — the internal components and
  the order `validateMdoc` composes them in.
- [docs/validation.md](docs/validation.md) — the complete validation rules
  reference, with limits and exact error messages traced to source.
- [docs/release.md](docs/release.md) — how a merge to `main` becomes a
  published npm package.
- [CONTRIBUTING.md](CONTRIBUTING.md) — the human starting point for setting up
  and contributing.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) to get set up
and [AGENTS.md](AGENTS.md) for the canonical conventions.

## Licence

[MIT License](LICENSE)
