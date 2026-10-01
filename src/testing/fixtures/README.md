# Test fixtures

## `external-credential.txt`

A real, base64url-encoded mdoc credential used by the end-to-end test in
`src/validateMdoc.test.ts` ("accepts a valid credential from an external issuer").
Its purpose is to prove `validateMdoc` accepts a credential produced by a real
issuer, not just one built in-repo by `TestMdocBuilder`.

- **Source:** [Example Credential Issuer (CRI)] dev account. (https://example-credential-issuer.wallet-onboarding.dev.account.gov.uk/.well-known/openid-credential-issuer).
- **docType:** `uk.gov.account.wallet-onboarding.example-credential-issuer.simplemdoc.1`
- **Format:** single line, base64url, no padding. The test `.trim()`s trailing
  whitespace before decoding.

### Validity note

The credential carries fixed `validityInfo` dates, so the test pins the clock
(`jest.useFakeTimers().setSystemTime(new Date("2026-09-22T15:30:00Z"))`) to a
time inside its validity window. If this fixture is ever regenerated, update
that timestamp to fall within the new credential's `validFrom`/`validUntil`
range, or the validity checks in `validateValidityInfo` will fail.

Do not edit the `.txt` file by hand — it is signed data and any change will
break the issuer signature verification.
