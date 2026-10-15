# Validation rules reference

This is the complete, rule-by-rule reference for what `validateMdoc` accepts
and rejects. Every limit, constant name, and error message below is transcribed
from source. For how to install and use the library, see
[README.md](../README.md); for the order the components run in, see
[architecture.md](architecture.md); for the conventions that govern changes to
this validator, see [AGENTS.md](../AGENTS.md).

> When you change a validation rule, update this document in the same change.
> It is the single home for limits and exact messages.

## Entry point and contract

`validateMdoc(credential: string): Promise<void>` (`src/validateMdoc.ts`)
resolves when the credential is valid and throws when it is not. It does not
return a boolean. All failures are thrown as `MdocValidationError`
(`src/MdocValidationError.ts`), an `Error` subclass carrying a string `code`
(default `"VALIDATION_FAILED"`).

Two mechanisms raise failures:

- **Schema parsing** via `parseSchema(schema, data, label)`
  (`src/parseSchema.ts`). It runs `schema.safeParse(data)` and, on failure,
  throws a single `INVALID_SCHEMA` error whose message aggregates **every** Zod
  issue for that schema (Zod collects all issues for one `safeParse`).
- **Custom validators** in `src/nameSpaces.ts` and `src/issuerAuth.ts`. These
  throw directly and **stop at the first failure** (each check `throw`s before
  the next runs). The one exception is `validateValidityInfo`, which
  **aggregates** all date errors into a single `INVALID_VALIDITY_INFO` message.

### Does it collect all violations or stop at the first?

| Layer                                        | Behaviour                                                            |
| -------------------------------------------- | -------------------------------------------------------------------- |
| Zod schema (`parseSchema`)                   | Collects all issues for that schema; joins them with `"; "`.         |
| `elementValueSchema` homogeneity refinements | Stop at the first offending element (`return` after `ctx.addIssue`). |
| `validateNamespaces`                         | Stops at the first duplicate (`throw`).                              |
| `validateIssuerAuth` sub-steps               | Run in sequence; the first failing step throws and halts.            |
| `validateValidityInfo`                       | Collects all date errors, then throws one message.                   |

### Time is captured at call time

`validateValidityInfo` (`src/issuerAuth.ts`) reads `const now = new Date()` at
the moment it runs. The same credential can be valid now and invalid later (or
vice versa). All validity-info comparisons use that single `now`.

## Error shape and field-path notation

Schema failures (`INVALID_SCHEMA`) have the message form:

```
<label> does not comply with schema - <path>: <message>; <path>: <message>; ...
```

- `<label>` is the structure being parsed (e.g. `IssuerSigned`,
  `MobileSecurityObject`, `IssuerSignedItem`, `MobileSecurityObjectBytes`).
- `<path>` is `issue.path.join("/")`, or the literal `root` when the path is
  empty (top-level failure). Source: `src/parseSchema.ts`.
- Multiple issues are joined by `"; "`.

Example: parsing `"not an object"` as a top-level object yields a `root: ...`
path; a bad `id` field yields an `id: ...` path (`src/parseSchema.test.ts`).

## Error codes

| Code                          | Source                   | Raised when                                              |
| ----------------------------- | ------------------------ | -------------------------------------------------------- |
| `INVALID_BASE64URL`           | `validateMdoc.ts`        | Credential string fails base64url decode.                |
| `INVALID_CBOR`                | `decodeCbor.ts`          | Decoded bytes are not valid CBOR.                        |
| `INVALID_SCHEMA`              | `parseSchema.ts`         | A structure fails its Zod schema.                        |
| `INVALID_DIGEST_IDS`          | `nameSpaces.ts`          | Duplicate `digestID` within a namespace.                 |
| `INVALID_ELEMENT_IDENTIFIERS` | `nameSpaces.ts`          | Duplicate `elementIdentifier` within a namespace.        |
| `INVALID_PROTECTED_HEADER`    | `issuerAuth.ts`          | Protected header missing, malformed, or not ES256.       |
| `INVALID_UNPROTECTED_HEADER`  | `issuerAuth.ts`          | Unprotected header / `x5chain` missing or unparseable.   |
| `INVALID_SIGNATURE`           | `issuerAuth.ts`          | Issuer signature does not verify.                        |
| `INVALID_VALIDITY_INFO`       | `issuerAuth.ts`          | One or more validity-info dates fail the temporal rules. |
| `INVALID_DIGESTS`             | `issuerAuth.ts`          | A presented item does not match an MSO digest.           |
| `INVALID_DEVICE_KEY`          | `issuerAuth.ts`          | Device key is not a valid EC2 / P-256 key.               |
| `VALIDATION_FAILED`           | `MdocValidationError.ts` | Default code; uncategorised failure.                     |

## Input decoding

| Stage     | Rule                                                                                                  | Message / code                                                                   |
| --------- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| base64url | The credential string must be valid base64url.                                                        | `Failed to decode base64url encoded credential - <reason>` / `INVALID_BASE64URL` |
| CBOR      | Decoded bytes must be valid CBOR. Decoding uses `rejectDuplicateKeys: true` and `saveOriginal: true`. | `<label> is not valid CBOR - <reason>` / `INVALID_CBOR`                          |

CBOR tag handling (`src/decodeCbor.ts`, `src/constants/tags.ts`): the default
decoders for tag `0` (date-time) and tag `1004` (full-date) are overridden so
the values stay wrapped in a `Tag` object instead of being auto-converted to
`Date`. This lets the schema verify the tag number and the string format
explicitly. Tag `24` (`ENCODED_CBOR_DATA`) marks embedded CBOR byte strings.

## `IssuerSigned` (top-level)

Source: `src/schemas/issuerSignedSchema.ts`, parsed with label `IssuerSigned`.
The object is `.strict()` — unknown top-level keys are rejected.

| Field                         | Rule                                                                                                       | Limit / constant           | Message                                                                            |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------- | ---------------------------------------------------------------------------------- |
| `nameSpaces`                  | Record keyed by namespace, values are arrays of encoded items.                                             | —                          | —                                                                                  |
| `nameSpaces` keys             | Non-empty, ≤256 chars, Latin-1 only.                                                                       | `latin1StringMax256`       | framework default + `must contain only Latin1 (ISO/IEC 8859-1) characters`         |
| `nameSpaces` values           | Each array must have ≥1 item.                                                                              | min 1                      | `must NOT have fewer than 1 items`                                                 |
| `nameSpaces` object           | Must have ≥1 property.                                                                                     | refine                     | `must NOT have fewer than 1 properties`                                            |
| `nameSpaces` array elements   | Each must be a tag-24 (encoded CBOR) with `Uint8Array` contents.                                           | `encodedDataTag`           | `must be tagged with 24 (encoded CBOR data)` / `tag contents must be a Uint8Array` |
| `issuerAuth`                  | A 4-tuple `[protectedHeader, unprotectedHeader, payload, signature]` (COSE_Sign1).                         | tuple                      | framework default                                                                  |
| `issuerAuth[0]`, `[2]`, `[3]` | `Uint8Array`.                                                                                              | `z.instanceof(Uint8Array)` | framework default                                                                  |
| `issuerAuth[1]`               | `Map<number, Uint8Array>`. Constraining values to `bstr` is what limits `x5chain` to a single certificate. | `z.map(...)`               | framework default                                                                  |

## `IssuerSignedItem` (per namespace entry)

Source: `src/schemas/issuerSignedItemSchema.ts`, parsed with label
`IssuerSignedItem` (decoded from the tag-24 bytes). The object is `.strict()`.

| Field               | Rule                                                                     | Limit / constant                   | Message                             |
| ------------------- | ------------------------------------------------------------------------ | ---------------------------------- | ----------------------------------- |
| `digestID`          | Integer, non-negative, `< 2^31`. Spec: digest IDs are smaller than 2^31. | `.int().nonnegative().lt(2 ** 31)` | framework default                   |
| `elementIdentifier` | Non-empty, ≤256 chars, Latin-1 only.                                     | `latin1StringMax256`               | framework default + Latin-1 message |
| `elementValue`      | A valid `DataElementValue` (see below).                                  | `elementValueSchema`               | per-union messages                  |
| `random`            | `Uint8Array` of ≥16 bytes. Spec: ≥16 bytes of randomness per item.       | refine `r.length >= 16`            | `random must be at least 16 bytes`  |

## `DataElementValue` (`elementValue`)

Source: `src/schemas/elementValueSchema.ts` and `src/schemas/constants.ts`
(`ELEMENT_VALUE_LIMITS`). `elementValueSchema` is a union of four shapes. `null`
and `undefined` are rejected (not members of the union). Nested arrays and
maps-of-maps are rejected implicitly because their inner values fail the
primitive-homogeneity check.

### Primitive scalars

| Primitive | Rule                                                                                  | Limit (`ELEMENT_VALUE_LIMITS`)                                                 | Message                                                                                                                                         |
| --------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| string    | Latin-1, 1–150 chars.                                                                 | `string.minLength` 1, `string.maxLength` 150                                   | `must not be empty` / `must not exceed 150 characters` + Latin-1 message                                                                        |
| number    | Finite, within safe-integer range (NaN/Infinity rejected by `z.number()`).            | `number.min` `Number.MIN_SAFE_INTEGER`, `number.max` `Number.MAX_SAFE_INTEGER` | framework default                                                                                                                               |
| boolean   | `z.boolean()`.                                                                        | —                                                                              | framework default                                                                                                                               |
| date-time | Tag 0, string contents, RFC 3339 UTC `YYYY-MM-DDTHH:MM:SSZ` (length 20, precision 0). | `dateTimeTag`                                                                  | `must be tagged with 0 (date-time)` / `tag contents must be a string` / `tag contents must be an RFC 3339 UTC date-time (YYYY-MM-DDTHH:MM:SSZ)` |
| full-date | Tag 1004, string contents, RFC 3339 `YYYY-MM-DD` (length 10).                         | `fullDateTag`                                                                  | `must be tagged with 1004 (full-date)` / `tag contents must be a string` / `tag contents must be an RFC 3339 full-date (YYYY-MM-DD)`            |
| bytes     | `Uint8Array`, 1 byte–1,572,864 bytes (1.5 MB).                                        | `uint8Array.minByteLength` 1, `uint8Array.maxByteLength` 1572864               | `must not be empty` / `must not exceed 1572864 bytes`                                                                                           |

### Collections

All collection bounds come from `collections` in `ELEMENT_VALUE_LIMITS`:
`minLength` 1, `maxLength` 256.

| Shape                    | Rule                                                                                                                | Message                                                                                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| array of primitives      | 1–256 entries; every element a valid primitive; all the same primitive type.                                        | `must not be empty` / `must not exceed 256 entries` / `all values must be valid primitives` / `all values must be the same primitive type`                            |
| `Map<string, primitive>` | 1–256 entries; all keys strings and Latin-1; values homogeneous primitives.                                         | `must not be empty` / `must not exceed 256 entries` / `all keys must be strings` / `keys must contain only Latin1 (ISO/IEC 8859-1) characters` / homogeneity messages |
| array of maps            | 1–256 entries; each inner map 1–256 with Latin-1 string keys; values flattened across all maps must be homogeneous. | same messages as above                                                                                                                                                |

Homogeneity is enforced by `checkHomogeneousPrimitives`: each value is first
classified (`classifyPrimitive`) and then re-parsed by `primitiveScalarSchema`
to enforce the bounds; a `null` classification (e.g. a nested array or a map
inside a value position) triggers `all values must be valid primitives`.

## `MobileSecurityObject` (MSO)

Source: `src/schemas/mobileSecurityObjectSchema.ts`. The MSO is decoded from the
`issuerAuth` payload: the payload is first parsed as a tag-24
`MobileSecurityObjectBytes`, then its contents are decoded and parsed as
`MobileSecurityObject` (`parseMobileSecurityObject` in `src/issuerAuth.ts`). The
object and its nested objects are `.strict()`.

| Field                                        | Rule                                                                                     | Limit / constant                 | Message                                 |
| -------------------------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------- | --------------------------------------- |
| `version`                                    | Literal `"1.0"`.                                                                         | `z.literal("1.0")`               | framework default                       |
| `digestAlgorithm`                            | Literal `"SHA-256"` (only SHA-256 supported).                                            | `z.literal("SHA-256")`           | framework default                       |
| `deviceKeyInfo.deviceKey`                    | `Map` (type/curve/coords checked later in `validateDeviceKey`).                          | `z.map(...)`                     | framework default                       |
| `deviceKeyInfo.keyAuthorizations.nameSpaces` | Array of strings, ≥1, no duplicates. `.strict()` rejects the `dataElements` alternative. | min 1 + refine                   | `must NOT have duplicate items`         |
| `valueDigests`                               | Record of namespace → `Map<number, Uint8Array>`; ≥1 property.                            | `latin1StringMax256` keys        | `must NOT have fewer than 1 properties` |
| `docType`                                    | Non-empty, ≤128 chars, Latin-1 only.                                                     | `latin1StringMax128`             | framework default + Latin-1 message     |
| `validityInfo.signed/validFrom/validUntil`   | Tag-0 date-time (structure only; ordering checked later).                                | `dateTimeTag`                    | date-time messages                      |
| `validityInfo.expectedUpdate`                | Optional tag-0 date-time.                                                                | `dateTimeTag.optional()`         | date-time messages                      |
| `status.status_list.idx`                     | Integer, 0–4294967295 (`UINT32_MAX`, 2^32-1).                                            | `z.int().min(0).max(UINT32_MAX)` | framework default                       |
| `status.status_list.uri`                     | URL, ≤2048 chars.                                                                        | `z.url().max(2048)`              | framework default                       |

`status` is required here even though not every mdoc carries it; credentials
issued without `status` are rejected.

## Namespace cross-item rules

Source: `src/nameSpaces.ts` (`validateNamespaces`). After schema parsing, each
namespace's items are checked for uniqueness. Stops at the first duplicate.

| Rule                                                 | Message                                               | Code                          |
| ---------------------------------------------------- | ----------------------------------------------------- | ----------------------------- |
| No duplicate `digestID` within a namespace.          | `Duplicate digest ID <id> in namespace <ns>`          | `INVALID_DIGEST_IDS`          |
| No duplicate `elementIdentifier` within a namespace. | `Duplicate element identifier <id> in namespace <ns>` | `INVALID_ELEMENT_IDENTIFIERS` |

## Issuer authentication (`validateIssuerAuth`)

Source: `src/issuerAuth.ts`. Runs in this order; the first failing step throws.

### 1. Protected header (`validateProtectedHeader`)

The protected header bytes are CBOR-decoded and must be a `Map` with exactly
one entry: `alg` (`COSE_HEADER_PARAMETERS.ALG` = 1) set to `-7`
(`COSE_ALGORITHMS.ES256`).

| Rule                      | Message                                                 | Code                       |
| ------------------------- | ------------------------------------------------------- | -------------------------- |
| Decoded value is a `Map`. | `Protected header is not a Map`                         | `INVALID_PROTECTED_HEADER` |
| Exactly one parameter.    | `Protected header contains unexpected extra parameters` | `INVALID_PROTECTED_HEADER` |
| Contains `alg` (1).       | `Protected header missing "alg" (1)`                    | `INVALID_PROTECTED_HEADER` |
| `alg` is `-7`.            | `Protected header "alg" must be -7 (ES256)`             | `INVALID_PROTECTED_HEADER` |

### 2. Unprotected header / signing certificate (`validateUnprotectedHeader`)

The unprotected header must contain exactly one parameter, `x5chain`
(`COSE_HEADER_PARAMETERS.X5_CHAIN` = 33), which must parse as a single X.509
certificate. Because the schema types the value as `bstr`, only a
single-certificate `x5chain` is representable — multi-certificate chains are
rejected.

| Rule                     | Message                                                                      | Code                         |
| ------------------------ | ---------------------------------------------------------------------------- | ---------------------------- |
| Exactly one parameter.   | `Unprotected header contains unexpected extra parameters`                    | `INVALID_UNPROTECTED_HEADER` |
| Contains `x5chain` (33). | `Unprotected header missing "x5chain" (33)`                                  | `INVALID_UNPROTECTED_HEADER` |
| Parses as X.509.         | `Failed to parse document signing certificate as X509Certificate - <reason>` | `INVALID_UNPROTECTED_HEADER` |

### 3. Signature (`verifySignature`)

Builds the COSE `Signature1` structure `["Signature1", protectedHeader,
<empty>, payload]`, CBOR-encodes it, and verifies with `sha256` and
`dsaEncoding: "ieee-p1363"` against the certificate's public key.

| Rule                         | Message                                      | Code                |
| ---------------------------- | -------------------------------------------- | ------------------- |
| Signature verifies.          | `Signature not verified`                     | `INVALID_SIGNATURE` |
| Verification does not throw. | `Signature could not be verified - <reason>` | `INVALID_SIGNATURE` |

### 4. Validity info (`validateValidityInfo`)

Reads `now = new Date()` and compares the tag-0 date strings. Aggregates all
failures into one message joined by `"; "`.

| Condition                                             | Message fragment                                                          |
| ----------------------------------------------------- | ------------------------------------------------------------------------- |
| `signed` in the future                                | `'signed' (<v>) must be in the past`                                      |
| `validFrom` in the future                             | `'validFrom' (<v>) must be in the past`                                   |
| `validUntil` not in the future (`<= now`)             | `'validUntil' (<v>) must be in the future`                                |
| `validFrom` earlier than `signed`                     | `'validFrom' (<v>) must be equal or later than 'signed' (<v>)`            |
| `expectedUpdate` after `validUntil` (only if present) | `'expectedUpdate' (<v>) must be less than or equal to 'validUntil' (<v>)` |

Wrapper message: `One or more dates are invalid - <joined fragments>` /
`INVALID_VALIDITY_INFO`.

### 5. Digest matching (`validateDigestsMatchMso`)

Selective disclosure: every presented item must match an MSO digest; MSO
digests with no presented item are allowed. For each presented item, the
original `IssuerSignedItemBytes` (recovered via `getEncoded`, enabled by
`saveOriginal`) are hashed with SHA-256 and compared against the MSO digest for
that `digestID`. The hash is computed over the bytes as received, never a
re-encode (a re-encode is not guaranteed to be byte-identical).

| Rule                                 | Message                                                                              | Code              |
| ------------------------------------ | ------------------------------------------------------------------------------------ | ----------------- |
| MSO has digests for the namespace.   | `No digests found for namespace <ns>`                                                | `INVALID_DIGESTS` |
| Original bytes recoverable.          | `Could not recover original bytes for an item in namespace <ns>`                     | `INVALID_DIGESTS` |
| MSO has a digest for the `digestID`. | `No digest found for digest ID <id> in MSO namespace <ns>`                           | `INVALID_DIGESTS` |
| Computed digest equals MSO digest.   | `Digest mismatch for element identifier <eid> with digest ID <id> in namespace <ns>` | `INVALID_DIGESTS` |

### 6. Device key (`validateDeviceKey`)

The device key `Map` must contain exactly the keys `[1, -1, -2, -3]`
(`COSE_KEY_PARAMETERS` KTY, EC2_CRV, EC2_X, EC2_Y), be EC2 (kty `2`) on P-256
(crv `1`), with `Uint8Array` x and y coordinates that import as a valid P-256
ECDSA key.

| Rule                            | Message                                                   | Code                 |
| ------------------------------- | --------------------------------------------------------- | -------------------- |
| Exactly keys `[1, -1, -2, -3]`. | `DeviceKey must contain exactly the keys [1, -1, -2, -3]` | `INVALID_DEVICE_KEY` |
| `kty` (1) is EC2 (2).           | `DeviceKey key type (1) must be EC2 (Elliptic Curve) (2)` | `INVALID_DEVICE_KEY` |
| `crv` (-1) is P-256 (1).        | `DeviceKey curve (-1) must be P-256 (1)`                  | `INVALID_DEVICE_KEY` |
| x (-2) is `Uint8Array`.         | `DeviceKey x-coordinate (-2) must be a Uint8Array`        | `INVALID_DEVICE_KEY` |
| y (-3) is `Uint8Array`.         | `DeviceKey y-coordinate (-3) must be a Uint8Array`        | `INVALID_DEVICE_KEY` |
| Imports as a P-256 ECDSA key.   | `Invalid elliptic curve key`                              | `INVALID_DEVICE_KEY` |

## For maintainers

Authoritative sources per concern:

| Concern                                                      | Source file(s)                                      |
| ------------------------------------------------------------ | --------------------------------------------------- |
| Centralised numeric/string/byte/collection limits            | `src/schemas/constants.ts` (`ELEMENT_VALUE_LIMITS`) |
| Latin-1 helpers and length-bounded string schemas            | `src/schemas/helpers/latin1.ts`                     |
| CBOR tag schemas (24, 0, 1004)                               | `src/schemas/cborTags.ts`, `src/constants/tags.ts`  |
| `DataElementValue` shapes + homogeneity                      | `src/schemas/elementValueSchema.ts`                 |
| Per-item schema                                              | `src/schemas/issuerSignedItemSchema.ts`             |
| Top-level `IssuerSigned` schema                              | `src/schemas/issuerSignedSchema.ts`                 |
| MSO schema (incl. `UINT32_MAX`, `status`)                    | `src/schemas/mobileSecurityObjectSchema.ts`         |
| COSE constants (alg, header labels, key params/types, curve) | `src/constants/cose.ts`                             |
| Namespace duplicate checks                                   | `src/nameSpaces.ts`                                 |
| Signature, header, validity, digest, device-key checks       | `src/issuerAuth.ts`                                 |
| CBOR decode options and tag overrides                        | `src/decodeCbor.ts`                                 |
| Schema error aggregation and field-path notation             | `src/parseSchema.ts`                                |
| Error type and codes                                         | `src/MdocValidationError.ts`                        |

Rule categories to keep in mind when editing:

- **Framework-default messages** come from Zod built-ins (e.g. `z.literal`,
  `z.int().nonnegative().lt(...)`, tuple shape). Changing the schema changes the
  message.
- **Custom messages** are the explicit strings passed to `.refine`,
  `.min`/`.max`, `ctx.addIssue`, or thrown in the validators. These are the
  exact strings above and are asserted by the `*.test.ts` suites.
- **Implicit rejections** are not spelled out by a dedicated message. Nested
  arrays and maps-of-maps are rejected because their inner values fail the
  primitive-homogeneity check (`all values must be valid primitives`), not by a
  separate "no nesting" rule. `.strict()` on each object rejects unknown keys
  with Zod's unrecognized-keys message.
