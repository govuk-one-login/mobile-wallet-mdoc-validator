import { Tag } from "cbor2";
import { MdocValidationError } from "./MdocValidationError";
import { TestMdocBuilder } from "./TestMdocBuilder";
import { validateIssuerAuth } from "./issuerAuth";

const validate = (builder: TestMdocBuilder) => {
  const { issuerAuth, nameSpaces } = builder.buildIssuerSigned();
  return validateIssuerAuth(issuerAuth, nameSpaces);
};

describe("validateIssuerAuth", () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(new Date("2025-09-10T15:30:00Z"));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("accepts a valid issuerAuth", async () => {
    await expect(validate(new TestMdocBuilder())).resolves.toBeUndefined();
  });

  describe("protected header", () => {
    it("rejects a protected header that is not a Map", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withProtectedHeader(
            "not a map" as unknown as Map<unknown, unknown>,
          ),
        ),
      ).rejects.toThrow("Protected header is not a Map");
    });

    it("rejects when there is more than one parameter", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withProtectedHeader(
            new Map().set(1, -7).set(2, "b"),
          ),
        ),
      ).rejects.toThrow(
        "Protected header contains unexpected extra parameters",
      );
    });

    it("rejects a missing alg (1)", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withProtectedHeader(new Map().set(2, -7)),
        ),
      ).rejects.toThrow('Protected header missing "alg" (1)');
    });

    it("rejects an alg other than ES256 (-7)", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withProtectedHeader(new Map().set(1, 7)),
        ),
      ).rejects.toThrow('Protected header "alg" must be -7 (ES256)');
    });
  });

  describe("unprotected header", () => {
    it("rejects when there is more than one parameter", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withUnprotectedHeader(
            new Map().set(33, new Uint8Array()).set(2, new Uint8Array()),
          ),
        ),
      ).rejects.toThrow(
        "Unprotected header contains unexpected extra parameters",
      );
    });

    it("rejects a missing x5chain (33)", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withUnprotectedHeader(
            new Map().set(1, new Uint8Array()),
          ),
        ),
      ).rejects.toThrow('Unprotected header missing "x5chain" (33)');
    });

    it("rejects a certificate that is not valid X.509", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withUnprotectedHeader(
            new Map().set(33, new Uint8Array()),
          ),
        ),
      ).rejects.toThrow(
        /Failed to parse document signing certificate as X509Certificate/,
      );
    });
  });

  describe("signature", () => {
    it("rejects a signature that does not verify", async () => {
      await expect(
        validate(new TestMdocBuilder().withMismatchedSigningCertificate()),
      ).rejects.toThrow("Signature not verified");
    });
  });

  describe("value digests", () => {
    it("rejects when item digest is not in the MSO", async () => {
      await expect(
        validate(new TestMdocBuilder().withoutDigest("title")),
      ).rejects.toThrow(
        "No digest found for digest ID 40 in MSO namespace org.test.namespace.1",
      );
    });

    it("rejects a digest mismatch", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withMismatchedDigest(
            "family_name",
            new Uint8Array(Buffer.from("incorrect-digest")),
          ),
        ),
      ).rejects.toThrow(
        "Digest mismatch for element identifier family_name with digest ID 10 in namespace org.test.namespace.2",
      );
    });
  });

  describe("device key", () => {
    it("rejects unexpected keys", async () => {
      await expect(
        validate(new TestMdocBuilder().withDeviceKeyParameter(999, 1)),
      ).rejects.toThrow(
        "DeviceKey must contain exactly the keys [1, -1, -2, -3]",
      );
    });

    it("rejects a key type (1) other than EC2 (2)", async () => {
      await expect(
        validate(new TestMdocBuilder().withDeviceKeyParameter(1, 1)),
      ).rejects.toThrow(
        "DeviceKey key type (1) must be EC2 (Elliptic Curve) (2)",
      );
    });

    it("rejects a curve (-1) other than P-256 (1)", async () => {
      await expect(
        validate(new TestMdocBuilder().withDeviceKeyParameter(-1, 2)),
      ).rejects.toThrow("DeviceKey curve (-1) must be P-256 (1)");
    });

    it("rejects an x-coordinate (-2) that is not bytes", async () => {
      await expect(
        validate(new TestMdocBuilder().withDeviceKeyParameter(-2, 123)),
      ).rejects.toThrow("DeviceKey x-coordinate (-2) must be a Uint8Array");
    });

    it("rejects a y-coordinate (-3) that is not bytes", async () => {
      await expect(
        validate(new TestMdocBuilder().withDeviceKeyParameter(-3, "string")),
      ).rejects.toThrow("DeviceKey y-coordinate (-3) must be a Uint8Array");
    });

    it("rejects coordinates that are not a valid public key", async () => {
      await expect(
        validate(
          new TestMdocBuilder()
            .withDeviceKeyParameter(-2, new Uint8Array())
            .withDeviceKeyParameter(-3, new Uint8Array()),
        ),
      ).rejects.toThrow("Invalid elliptic curve key");
    });
  });

  describe("validity info", () => {
    it("rejects signed and validFrom in the future", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withValidityInfo({
            signed: new Tag(0, "2025-09-10T15:40:00Z"),
            validFrom: new Tag(0, "2025-09-10T15:40:00Z"),
          }),
        ),
      ).rejects.toThrow(
        "One or more dates are invalid - 'signed' (2025-09-10T15:40:00Z) must be in the past,'validFrom' (2025-09-10T15:40:00Z) must be in the past",
      );
    });

    it("rejects validFrom before signed", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withValidityInfo({
            signed: new Tag(0, "2025-09-10T15:25:00Z"),
            validFrom: new Tag(0, "2025-09-10T15:20:00Z"),
          }),
        ),
      ).rejects.toThrow(
        "One or more dates are invalid - 'validFrom' (2025-09-10T15:20:00Z) must be equal or later than 'signed' (2025-09-10T15:25:00Z)",
      );
    });

    it("rejects validUntil in the past", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withValidityInfo({
            validUntil: new Tag(0, "2025-09-09T15:30:00Z"),
          }),
        ),
      ).rejects.toThrow(
        "One or more dates are invalid - 'validUntil' (2025-09-09T15:30:00Z) must be in the future",
      );
    });

    it("rejects expectedUpdate after validUntil", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withValidityInfo({
            expectedUpdate: new Tag(0, "2027-01-01T00:00:00Z"),
            validUntil: new Tag(0, "2026-09-10T15:20:00Z"),
          }),
        ),
      ).rejects.toThrow(
        "One or more dates are invalid - 'expectedUpdate' (2027-01-01T00:00:00Z) must be less than or equal to 'validUntil' (2026-09-10T15:20:00Z)",
      );
    });

    it("accepts expectedUpdate before validUntil", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withValidityInfo({
            expectedUpdate: new Tag(0, "2026-01-01T00:00:00Z"),
          }),
        ),
      ).resolves.toBeUndefined();
    });

    it("accepts expectedUpdate equal to validUntil", async () => {
      await expect(
        validate(
          new TestMdocBuilder().withValidityInfo({
            expectedUpdate: new Tag(0, "2026-09-10T15:20:00Z"),
          }),
        ),
      ).resolves.toBeUndefined();
    });
  });

  it("throws MdocValidationError", async () => {
    await expect(
      validate(new TestMdocBuilder().withProtectedHeader(new Map().set(1, 7))),
    ).rejects.toThrow(MdocValidationError);
  });
});
