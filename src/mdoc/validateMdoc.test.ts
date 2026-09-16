import { validateMdoc } from "./validateMdoc";
import { TestMdocBuilder } from "./TestMdocBuilder";
import { MdocValidationError } from "./MdocValidationError";
import { Tag } from "cbor2";
import { base64url } from "jose";
import { X509Certificate } from "node:crypto";
import { ZodError, type ZodIssue } from "zod";
import * as issuerSignedSchemaModule from "./schemas/issuerSignedSchema";
import * as mobileSecurityObjectSchemaModule from "./schemas/mobileSecurityObjectSchema";

describe("validateMdoc", () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(new Date("2025-09-10T15:30:00Z"));
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  describe("Encoding", () => {
    it("should throw MdocValidationError for invalid base64url encoding", async () => {
      expect.assertions(2);
      try {
        await validateMdoc("invalid@base64url!");
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toBe(
          "Failed to decode base64url encoded credential - The input to be decoded is not correctly encoded.",
        );
      }
    });

    it("should throw MdocValidationError for invalid CBOR encoding", async () => {
      expect.assertions(2);
      try {
        await validateMdoc(base64url.encode("invalidCbor"));
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toBe(
          "Failed to decode CBOR encoded credential - Extra data in input",
        );
      }
    });
  });

  describe("Tags", () => {
    it("should throw MdocValidationError when an IssuerSignedItem in namespace test.namespace.2 is not tagged with 24", async () => {
      const credential = new TestMdocBuilder()
        .withUntaggedIssuerSignedItemBytes("family_name")
        .build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toContain(
          "TaggedIssuerSigned does not comply with schema - nameSpaces/org.test.namespace.2/0",
        );
      }
    });

    it("should throw MdocValidationError when an IssuerSignedItem in namespace test.namespace.1 is not tagged with 24", async () => {
      const credential = new TestMdocBuilder()
        .withUntaggedIssuerSignedItemBytes("portrait")
        .build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toContain(
          "TaggedIssuerSigned does not comply with schema - nameSpaces/org.test.namespace.1/0",
        );
      }
    });

    it("should throw MdocValidationError when MobileSecurityObjectBytes missing tag '24'", async () => {
      const credential = new TestMdocBuilder().withUntaggedMsoBytes().build();

      await expect(validateMdoc(credential)).rejects.toThrow();
    });

    it("should throw MdocValidationError when 'signed' in ValidityInfo is not tagged with 0", async () => {
      const credential = new TestMdocBuilder()
        .withValidityInfo({
          signed: "2025-12-20T15:20:33Z",
        })
        .build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toContain(
          "MobileSecurityObject does not comply with schema",
        );
      }
    });

    it("should throw MdocValidationError when 'validFrom' in ValidityInfo is not tagged with 0", async () => {
      const credential = new TestMdocBuilder()
        .withValidityInfo({
          validFrom: "2025-12-20T15:20:33",
        })
        .build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toContain(
          "MobileSecurityObject does not comply with schema",
        );
      }
    });

    it("should throw MdocValidationError when 'validUntil' in ValidityInfo is not tagged with 0", async () => {
      const credential = new TestMdocBuilder()
        .withValidityInfo({
          validUntil: "2025-12-20T15:20:33",
        })
        .build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toContain(
          "MobileSecurityObject does not comply with schema",
        );
      }
    });
  });

  describe("IssuerSigned Schema", () => {
    it("should throw MdocValidationError with validation error including path", async () => {
      const zodIssues: ZodIssue[] = [
        {
          code: "invalid_type",
          path: ["path"],
          message: "must be a string",
          expected: "string",
          received: "number",
        },
      ];

      jest
        .spyOn(issuerSignedSchemaModule.taggedIssuerSignedSchema, "parse")
        .mockImplementation(() => {
          throw new ZodError(zodIssues);
        });

      const credential = new TestMdocBuilder().build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toBe(
          "TaggedIssuerSigned does not comply with schema - path: must be a string",
        );
      }
    });

    it("should throw MdocValidationError and default path to 'root' when path is empty", async () => {
      const zodIssues: ZodIssue[] = [
        {
          code: "invalid_type",
          path: [],
          message: "must be a string",
          expected: "string",
          received: "number",
        },
      ];

      jest
        .spyOn(issuerSignedSchemaModule.taggedIssuerSignedSchema, "parse")
        .mockImplementation(() => {
          throw new ZodError(zodIssues);
        });

      const credential = new TestMdocBuilder().build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toBe(
          "TaggedIssuerSigned does not comply with schema - root: must be a string",
        );
      }
    });

    it("should throw MdocValidationError with Zod validation message", async () => {
      const zodIssues: ZodIssue[] = [
        {
          code: "invalid_type",
          path: ["path"],
          message: "Expected string, received number",
          expected: "string",
          received: "number",
        },
      ];

      jest
        .spyOn(issuerSignedSchemaModule.taggedIssuerSignedSchema, "parse")
        .mockImplementation(() => {
          throw new ZodError(zodIssues);
        });

      const credential = new TestMdocBuilder().build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toBe(
          "TaggedIssuerSigned does not comply with schema - path: Expected string, received number",
        );
      }
    });

    it("should throw MdocValidationError with empty error details when issues array is empty", async () => {
      jest
        .spyOn(issuerSignedSchemaModule.taggedIssuerSignedSchema, "parse")
        .mockImplementation(() => {
          throw new ZodError([]);
        });

      const credential = new TestMdocBuilder().build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toBe(
          "TaggedIssuerSigned does not comply with schema - ",
        );
      }
    });
  });

  describe("Digest IDs", () => {
    it("should throw MdocValidationError when digest IDs within a namespace are not unique", async () => {
      const credential = new TestMdocBuilder()
        .withDigestId("given_name", 10)
        .withDigestId("family_name", 10)
        .build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toBe(
          "Digest IDs are not unique for namespace org.test.namespace.2",
        );
      }
    });

    it("should throw MdocValidationError when digest IDs within a namespace are not unique", async () => {
      const credential = new TestMdocBuilder()
        .withDigestId("portrait", 10)
        .withDigestId("title", 10)
        .build();

      expect.assertions(2);
      try {
        await validateMdoc(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as Error).message).toBe(
          "Digest IDs are not unique for namespace org.test.namespace.1",
        );
      }
    });
  });

  describe("IssuerAuth", () => {
    describe("Protected header", () => {
      it("should throw MdocValidationError when protected header is not a Map", async () => {
        const credential = new TestMdocBuilder()
          .withProtectedHeader("not a map" as unknown as Map<unknown, unknown>)
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "Protected header is not a Map",
          );
        }
      });

      it("should throw MdocValidationError when protected header has more than one key", async () => {
        const credential = new TestMdocBuilder()
          .withProtectedHeader(new Map().set(1, -7).set(2, "b"))
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "Protected header contains unexpected extra parameters - must contain only one",
          );
        }
      });

      it("should throw MdocValidationError when protected header is missing algorithm (1) key", async () => {
        const credential = new TestMdocBuilder()
          .withProtectedHeader(new Map().set(2, -7))
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            'Protected header missing "alg" (1)',
          );
        }
      });

      it("should throw MdocValidationError when protected header algorithm is not ES256 (-1)", async () => {
        const credential = new TestMdocBuilder()
          .withProtectedHeader(new Map().set(1, 7))
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            'Protected header "alg" must be -7 (ES256)',
          );
        }
      });
    });

    describe("Unprotected header", () => {
      it("should throw MdocValidationError when unprotected header has more than one key", async () => {
        const credential = new TestMdocBuilder()
          .withUnprotectedHeader(
            new Map().set(33, new Uint8Array()).set(2, new Uint8Array()),
          )
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "Unprotected header contains unexpected extra parameters - must contain only one",
          );
        }
      });

      it("should throw MdocValidationError when unprotected header is missing x5chain (33) key", async () => {
        const credential = new TestMdocBuilder()
          .withUnprotectedHeader(new Map().set(1, new Uint8Array()))
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            'Unprotected header missing "x5chain" (33)',
          );
        }
      });

      it("should throw MdocValidationError when certificate is not a valid X509 certificate", async () => {
        const credential = new TestMdocBuilder()
          .withUnprotectedHeader(new Map().set(33, new Uint8Array()))
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toEqual(
            expect.stringContaining(
              "Failed to parse document signing certificate as X509Certificate",
            ),
          );
        }
      });

      it("should throw MdocValidationError when MSO signature fails to verify", async () => {
        jest.useFakeTimers();
        jest.setSystemTime(new Date("2026-01-10T13:38:48Z"));

        const wrongDocumentSigningCertificate =
          new X509Certificate(`-----BEGIN CERTIFICATE-----
MIIB7TCCAZOgAwIBAgIUZpfeB6WGkUsUk13SiJX8i6vG1IEwCgYIKoZIzj0EAwIw
XDELMAkGA1UEBhMCVUsxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9u
MQ0wCwYDVQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MQ0wCwYDVQQDDARUZXN0MB4X
DTI2MDEwODEzMzkzNVoXDTI3MDEwODEzMzkzNVowTTELMAkGA1UEBhMCVUsxDzAN
BgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ0wCwYDVQQKDARUZXN0MQ0w
CwYDVQQLDARUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+jfaNAHbEm+P
2QbR6EMOj7+nILxkSJIani1RIPJI2X/NTtwJbMq6TN7X7f9BtK5DsioNOThMF/+t
1EFaLFPAuKNCMEAwHQYDVR0OBBYEFL0/RS4sYeY0F/AvLmHbEEv9NSG4MB8GA1Ud
IwQYMBaAFOuameupM0YpmgBT5Q4WxFe6TVMUMAoGCCqGSM49BAMCA0gAMEUCIEBO
RlvvhrfRUeNSJ0B18SsHCw1r4YUoJ206JZPFWxsRAiEA39zuNQ4ituFpufYFAUzb
h6XK6xERRLkY5jjINTt8TkU=
-----END CERTIFICATE-----`);
        const credential = new TestMdocBuilder()
          .withUnprotectedHeader(
            new Map().set(
              33,
              new Uint8Array(wrongDocumentSigningCertificate.raw),
            ),
          )
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe("Signature not verified");
        } finally {
          jest.useRealTimers();
        }
      });
    });

    describe("MSO Schema", () => {
      it("should throw MdocValidationError for MSO with validation error including path", async () => {
        const zodIssues: ZodIssue[] = [
          {
            code: "invalid_type",
            path: ["path"],
            message: "must be a string",
            expected: "string",
            received: "number",
          },
        ];

        jest
          .spyOn(
            mobileSecurityObjectSchemaModule.mobileSecurityObjectSchema,
            "parse",
          )
          .mockImplementation(() => {
            throw new ZodError(zodIssues);
          });

        const credential = new TestMdocBuilder().build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "MobileSecurityObject does not comply with schema - path: must be a string",
          );
        }
      });

      it("should throw MdocValidationError and default path to 'root' when path is empty", async () => {
        const zodIssues: ZodIssue[] = [
          {
            code: "invalid_type",
            path: [],
            message: "must be a string",
            expected: "string",
            received: "number",
          },
        ];

        jest
          .spyOn(
            mobileSecurityObjectSchemaModule.mobileSecurityObjectSchema,
            "parse",
          )
          .mockImplementation(() => {
            throw new ZodError(zodIssues);
          });

        const credential = new TestMdocBuilder().build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "MobileSecurityObject does not comply with schema - root: must be a string",
          );
        }
      });

      it("should throw MdocValidationError with Zod validation message", async () => {
        const zodIssues: ZodIssue[] = [
          {
            code: "invalid_type",
            path: ["path"],
            message: "Expected string, received number",
            expected: "string",
            received: "number",
          },
        ];

        jest
          .spyOn(
            mobileSecurityObjectSchemaModule.mobileSecurityObjectSchema,
            "parse",
          )
          .mockImplementation(() => {
            throw new ZodError(zodIssues);
          });

        const credential = new TestMdocBuilder().build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "MobileSecurityObject does not comply with schema - path: Expected string, received number",
          );
        }
      });

      it("should throw MdocValidationError with empty error details when issues array is empty", async () => {
        jest
          .spyOn(
            mobileSecurityObjectSchemaModule.mobileSecurityObjectSchema,
            "parse",
          )
          .mockImplementation(() => {
            throw new ZodError([]);
          });

        const credential = new TestMdocBuilder().build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "MobileSecurityObject does not comply with schema - ",
          );
        }
      });
    });

    describe("Value digests", () => {
      it("should throw MdocValidationError when the payload's ValueDigests is missing a digest", async () => {
        const credential = new TestMdocBuilder().withoutDigest("title").build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "No digest found for digest ID 40 in MSO namespace org.test.namespace.1",
          );
        }
      });

      it("should throw MdocValidationError when digests don't match", async () => {
        const credential = new TestMdocBuilder()
          .withMismatchedDigest(
            "family_name",
            new Uint8Array(Buffer.from("incorrect-digest")),
          )
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "Digest mismatch for element identifier family_name with digest ID 10 in namespace org.test.namespace.2 - Expected 696e636f72726563742d646967657374 but calculated 40cb668b10272f8f5e6160d4e968d95d0c090f47c90306ebe934776ac076caba",
          );
        }
      });
    });

    describe("Device key", () => {
      it("should throw MdocValidationError when it has invalid keys", async () => {
        const credential = new TestMdocBuilder()
          .withDeviceKeyParameter(999, 1)
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "DeviceKey must contain exactly the keys [1, -1, -2, -3]",
          );
        }
      });

      it("should throw MdocValidationError when key type (1) is not EC2 (2)", async () => {
        const credential = new TestMdocBuilder()
          .withDeviceKeyParameter(1, 1)
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "DeviceKey key type (1) must be EC2 (Elliptic Curve) (2)",
          );
        }
      });

      it("should throw MdocValidationError when curve (-1) is not P-256 (1)", async () => {
        const credential = new TestMdocBuilder()
          .withDeviceKeyParameter(-1, 2)
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "DeviceKey curve (-1) must be P-256 (1)",
          );
        }
      });

      it("should throw MdocValidationError when x-coordinate (-2) is not a Uint8Array", async () => {
        const credential = new TestMdocBuilder()
          .withDeviceKeyParameter(-2, 123)
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "DeviceKey x-coordinate (-2) must be a Uint8Array",
          );
        }
      });

      it("should throw MdocValidationError when y-coordinate (-3) is not a Uint8Array", async () => {
        const credential = new TestMdocBuilder()
          .withDeviceKeyParameter(-3, "string")
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "DeviceKey y-coordinate (-3) must be a Uint8Array",
          );
        }
      });

      it("should throw MdocValidationError when it is not a valid public key", async () => {
        const credential = new TestMdocBuilder()
          .withDeviceKeyParameter(-2, new Uint8Array())
          .withDeviceKeyParameter(-3, new Uint8Array())
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe("Invalid elliptic curve key");
        }
      });
    });

    describe("Validity info", () => {
      it("should throw MdocValidationError when 'signed' is in the future", async () => {
        const credential = new TestMdocBuilder()
          .withValidityInfo({
            signed: new Tag(0, "2025-09-10T15:40:00Z"),
            validFrom: new Tag(0, "2025-09-10T15:40:00Z"),
          })
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "One or more dates are invalid - 'signed' (2025-09-10T15:40:00Z) must be in the past,'validFrom' (2025-09-10T15:40:00Z) must be in the past",
          );
        }
      });

      it("should throw MdocValidationError when 'validFrom' is before 'signed'", async () => {
        const credential = new TestMdocBuilder()
          .withValidityInfo({
            signed: new Tag(0, "2025-09-10T15:25:00Z"),
            validFrom: new Tag(0, "2025-09-10T15:20:00Z"),
          })
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "One or more dates are invalid - 'validFrom' (2026-09-10T15:20:00Z) must be equal or later than 'signed' (2025-09-10T15:25:00Z)",
          );
        }
      });

      it("should throw MdocValidationError when 'validUntil' is in the past", async () => {
        const credential = new TestMdocBuilder()
          .withValidityInfo({
            validUntil: new Tag(0, "2025-09-09T15:30:00Z"),
          })
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "One or more dates are invalid - 'validUntil' (2025-09-09T15:30:00Z) must be in the future",
          );
        }
      });

      it("should throw MdocValidationError when 'expectedUpdate' is after 'validUntil'", async () => {
        const credential = new TestMdocBuilder()
          .withValidityInfo({
            expectedUpdate: new Tag(0, "2027-01-01T00:00:00Z"),
            validUntil: new Tag(0, "2026-09-10T15:20:00Z"),
          })
          .build();

        expect.assertions(2);
        try {
          await validateMdoc(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MdocValidationError);
          expect((error as Error).message).toBe(
            "One or more dates are invalid - 'expectedUpdate' (2027-01-01T00:00:00Z) must be less than or equal to 'validUntil' (2026-09-10T15:20:00Z)",
          );
        }
      });

      it("should not throw when 'expectedUpdate' is before 'validUntil'", async () => {
        const credential = new TestMdocBuilder()
          .withValidityInfo({
            expectedUpdate: new Tag(0, "2026-01-01T00:00:00Z"),
          })
          .build();

        expect(await validateMdoc(credential)).toBe(true);
      });

      it("should not throw when 'expectedUpdate' equals 'validUntil'", async () => {
        const credential = new TestMdocBuilder()
          .withValidityInfo({
            expectedUpdate: new Tag(0, "2026-09-10T15:20:00Z"),
          })
          .build();

        expect(await validateMdoc(credential)).toBe(true);
      });
    });
  });

  it("should return true when credential is valid", async () => {
    const credential = new TestMdocBuilder().build();
    expect(await validateMdoc(credential)).toBe(true);
  });
});
