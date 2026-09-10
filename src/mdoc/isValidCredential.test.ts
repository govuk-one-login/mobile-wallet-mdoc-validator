import { isValidCredential } from "./isValidCredential";
import { TestMDLBuilder } from "./TestMDLBuilder";
import { MDLValidationError } from "./MDLValidationError";
import { Tag } from "cbor2";
import { base64url } from "jose";
import * as ajvModule from "../ajv/ajvInstance";
import { X509Certificate } from "node:crypto";
import { ErrorObject, ValidateFunction } from "ajv";

describe("isValidCredential", () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(new Date("2025-09-10T15:30:00Z"));
  });

  afterEach(() => {
    jest.useRealTimers();
    ajvModule.resetAjvInstance();
    jest.restoreAllMocks();
  });

  describe("Encoding", () => {
    it("should throw MDLValidationError for invalid base64url encoding", async () => {
      expect.assertions(2);
      try {
        await isValidCredential("invalid@base64url!");
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "Failed to decode base64url encoded credential - The input to be decoded is not correctly encoded.",
        );
      }
    });

    it("should throw MDLValidationError for invalid CBOR encoding", async () => {
      expect.assertions(2);
      try {
        await isValidCredential(base64url.encode("invalidCbor"));
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "Failed to decode CBOR encoded credential - Extra data in input",
        );
      }
    });
  });

  describe("Tags", () => {
    it("should throw MDLValidationError when an IssuerSignedItem in namespace test.namespace.2 is not tagged with 24", async () => {
      const credential = new TestMDLBuilder()
        .withUntaggedIssuerSignedItemBytes("family_name")
        .build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain(
          "Failed to validate tags - IssuerSignedItem in namespace 'org.test.namespace.2' missing tag '24'",
        );
      }
    });

    it("should throw MDLValidationError when an IssuerSignedItem in namespace test.namespace.1 is not tagged with 24", async () => {
      const credential = new TestMDLBuilder()
        .withUntaggedIssuerSignedItemBytes("portrait")
        .build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "Failed to validate tags - IssuerSignedItem in namespace 'org.test.namespace.1' missing tag '24'",
        );
      }
    });

    it("should throw MDLValidationError when MobileSecurityObjectBytes missing tag '24'", async () => {
      const credential = new TestMDLBuilder().withUntaggedMsoBytes().build();

      await expect(isValidCredential(credential)).rejects.toThrow(
        "MobileSecurityObjectBytes missing tag",
      );
    });

    it("should throw MDLValidationError when 'signed' in ValidityInfo is not tagged with 0", async () => {
      const credential = new TestMDLBuilder()
        .withValidityInfo({
          signed: "2025-12-20T15:20:33Z",
        })
        .build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "Failed to validate tags - 'signed' in 'ValidityInfo' missing tag 0",
        );
      }
    });

    it("should throw MDLValidationError when 'validFrom' in ValidityInfo is not tagged with 0", async () => {
      const credential = new TestMDLBuilder()
        .withValidityInfo({
          validFrom: "2025-12-20T15:20:33",
        })
        .build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "Failed to validate tags - 'validFrom' in 'ValidityInfo' missing tag 0",
        );
      }
    });

    it("should throw MDLValidationError when 'validUntil' in ValidityInfo is not tagged with 0", async () => {
      const credential = new TestMDLBuilder()
        .withValidityInfo({
          validUntil: "2025-12-20T15:20:33",
        })
        .build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "Failed to validate tags - 'validUntil' in 'ValidityInfo' missing tag 0",
        );
      }
    });
  });

  describe("IssuerSigned Schema", () => {
    it("should throw MDLValidationError with AJV error", async () => {
      const mockValidator = jest
        .fn()
        .mockReturnValue(false) as unknown as ValidateFunction;
      mockValidator.errors = [
        {
          instancePath: "/path",
          message: "must be a string",
          data: 123,
          keyword: "key",
        } as unknown as ErrorObject,
      ];

      const mockAjv = {
        getSchema: jest.fn().mockReturnValue(undefined),
        addSchema: jest.fn().mockReturnThis(),
        compile: jest.fn().mockReturnValue(mockValidator),
      };

      jest.spyOn(ajvModule, "getAjvInstance").mockReturnValue(mockAjv as never);

      const credential = new TestMDLBuilder().build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "IssuerSigned does not comply with schema - /path: must be a string",
        );
      }
    });

    it("should throw MDLValidationError and default path to 'root' when instancePath is missing", async () => {
      const mockValidator = jest
        .fn()
        .mockReturnValue(false) as unknown as ValidateFunction;
      mockValidator.errors = [
        {
          instancePath: "",
          message: "must be a string",
          data: 123,
          keyword: "key",
        } as unknown as ErrorObject,
      ];

      const mockAjv = {
        getSchema: jest.fn().mockReturnValue(undefined),
        addSchema: jest.fn().mockReturnThis(),
        compile: jest.fn().mockReturnValue(mockValidator),
      };

      jest.spyOn(ajvModule, "getAjvInstance").mockReturnValue(mockAjv as never);

      const credential = new TestMDLBuilder().build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "IssuerSigned does not comply with schema - root: must be a string",
        );
      }
    });

    it("should throw MDLValidationError and default message to 'Unknown validation error' when message is missing", async () => {
      const mockValidator = jest
        .fn()
        .mockReturnValue(false) as unknown as ValidateFunction;
      mockValidator.errors = [
        {
          instancePath: "/path",
          message: undefined,
          data: 123,
          keyword: "key",
        } as unknown as ErrorObject,
      ];

      const mockAjv = {
        getSchema: jest.fn().mockReturnValue(undefined),
        addSchema: jest.fn().mockReturnThis(),
        compile: jest.fn().mockReturnValue(mockValidator),
      };

      jest.spyOn(ajvModule, "getAjvInstance").mockReturnValue(mockAjv as never);

      const credential = new TestMDLBuilder().build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "IssuerSigned does not comply with schema - /path: Unknown validation error",
        );
      }
    });

    it("should throw MDLValidationError with empty error details when validator.errors is undefined", async () => {
      const mockValidator = jest
        .fn()
        .mockReturnValue(false) as unknown as ValidateFunction;
      mockValidator.errors = undefined;

      const mockAjv = {
        getSchema: jest.fn().mockReturnValue(undefined),
        addSchema: jest.fn().mockReturnThis(),
        compile: jest.fn().mockReturnValue(mockValidator),
      };

      jest.spyOn(ajvModule, "getAjvInstance").mockReturnValue(mockAjv as never);

      const credential = new TestMDLBuilder().build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "IssuerSigned does not comply with schema - ",
        );
      }
    });
  });

  describe("Digest IDs", () => {
    it("should throw MDLValidationError when digest IDs within a namespace are not unique", async () => {
      const credential = new TestMDLBuilder()
        .withDigestId("given_name", 10)
        .withDigestId("family_name", 10)
        .build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "Digest IDs are not unique for namespace org.test.namespace.2",
        );
      }
    });

    it("should throw MDLValidationError when digest IDs within a namespace are not unique", async () => {
      const credential = new TestMDLBuilder()
        .withDigestId("portrait", 10)
        .withDigestId("title", 10)
        .build();

      expect.assertions(2);
      try {
        await isValidCredential(credential);
      } catch (error) {
        expect(error).toBeInstanceOf(MDLValidationError);
        expect((error as Error).message).toBe(
          "Digest IDs are not unique for namespace org.test.namespace.1",
        );
      }
    });
  });

  describe("IssuerAuth", () => {
    describe("Protected header", () => {
      it("should throw MDLValidationError when protected header is not a Map", async () => {
        const credential = new TestMDLBuilder()
          .withProtectedHeader("not a map")
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "Protected header is not a Map",
          );
        }
      });

      it("should throw MDLValidationError when protected header has more than one key", async () => {
        const credential = new TestMDLBuilder()
          .withProtectedHeader(new Map().set(1, -7).set(2, "b"))
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "Protected header contains unexpected extra parameters - must contain only one",
          );
        }
      });

      it("should throw MDLValidationError when protected header is missing algorithm (1) key", async () => {
        const credential = new TestMDLBuilder()
          .withProtectedHeader(new Map().set(2, -7))
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            'Protected header missing "alg" (1)',
          );
        }
      });

      it("should throw MDLValidationError when protected header algorithm is not ES256 (-1)", async () => {
        const credential = new TestMDLBuilder()
          .withProtectedHeader(new Map().set(1, 7))
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            'Protected header "alg" must be -7 (ES256)',
          );
        }
      });
    });

    describe("Unprotected header", () => {
      it("should throw MDLValidationError when unprotected header has more than one key", async () => {
        const credential = new TestMDLBuilder()
          .withUnprotectedHeader(
            new Map().set(33, new Uint8Array()).set(2, new Uint8Array()),
          )
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "Unprotected header contains unexpected extra parameters - must contain only one",
          );
        }
      });

      it("should throw MDLValidationError when unprotected header is missing x5chain (33) key", async () => {
        const credential = new TestMDLBuilder()
          .withUnprotectedHeader(new Map().set(1, new Uint8Array()))
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            'Unprotected header missing "x5chain" (33)',
          );
        }
      });

      it("should throw MDLValidationError when certificate is not a valid X509 certificate", async () => {
        const credential = new TestMDLBuilder()
          .withUnprotectedHeader(new Map().set(33, new Uint8Array()))
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toEqual(
            expect.stringContaining(
              "Failed to parse document signing certificate as X509Certificate",
            ),
          );
        }
      });

      it("should throw MDLValidationError when document signing certificate is a CA", async () => {
        const rootCertificate = `-----BEGIN CERTIFICATE-----
MIIB1zCCAX2gAwIBAgIUIatAsTQsYXy6Wrb1Cdp8tJ3RLC0wCgYIKoZIzj0EAwIw
QTELMAkGA1UEBhMCR0IxMjAwBgNVBAMMKW1ETCBFeGFtcGxlIElBQ0EgUm9vdCAt
IExPQ0FMIGVudmlyb25tZW50MB4XDTI1MDkwMjEwMjQyNVoXDTI4MDYyMjEwMjQy
NVowQTELMAkGA1UEBhMCR0IxMjAwBgNVBAMMKW1ETCBFeGFtcGxlIElBQ0EgUm9v
dCAtIExPQ0FMIGVudmlyb25tZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
mBxJk2MqFKn7c4MSEwlA8EUbMMxyU8DnPXwERUs4VjBF7534WDQQLCZBxvaYn73M
35NYkWiXO8oiRmWG9AzDn6NTMFEwHQYDVR0OBBYEFPY4eri7CuGrxh14YMTQe1qn
BVjoMB8GA1UdIwQYMBaAFPY4eri7CuGrxh14YMTQe1qnBVjoMA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgPJmIjY1hoYRHjBMgLeV0x+wWietEyBfx
zyaulhhqnewCIQCmJ0kwBidqVzCOIx5H8CaEHUnTA/ULJGC2DDFzT7s54A==
-----END CERTIFICATE-----`;

        const caCertificate = new X509Certificate(rootCertificate);
        const credential = new TestMDLBuilder()
          .withUnprotectedHeader(
            new Map().set(33, new Uint8Array(caCertificate.raw)),
          )
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "Document signing certificate must not be a CA certificate",
          );
        }
      });

      it("should throw MDLValidationError when document signing certificate is not valid at the current time", async () => {
        jest.useFakeTimers();
        jest.setSystemTime(new Date("2025-09-10T13:38:48Z"));
        // Current time: 2025-09-10, Certificate valid from: 2026-01-23
        const notYetValidCertificatePem = `-----BEGIN CERTIFICATE-----
MIIBaTCCAQ+gAwIBAgIURf+h7qmhNPgAaEaPTcVxS9VHCs8wCgYIKoZIzj0EAwIw
DTELMAkGA1UEBhMCR0IwHhcNMjYwMTIzMTkyMzMzWhcNMjcwMTIzMTkyMzMzWjAN
MQswCQYDVQQGEwJHQjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGeeOjZn8fE8
VlYczaP1WxltIBRFS7GYDd2tCwjnWQTb8bkcduDJgkUY5F7oSPIXXt62DxB6e5eN
8EvSn3nmQR6jTTBLMAkGA1UdEwQCMAAwHQYDVR0OBBYEFB44hqfYqP0ffiWBMv3/
FvTJh8vMMB8GA1UdIwQYMBaAFJXgNJAHxslWE68pACiQGvlY335IMAoGCCqGSM49
BAMCA0gAMEUCIQC2c028yzpQCh2Azw/YHpxOzn+ZxKvqpHrk8ysE7KY9ygIgZD51
P1oagJM6zj+3hIFOq8se0YLBI8S9sWUVsxluiN4=
-----END CERTIFICATE-----`;

        const notYetValidCertificate = new X509Certificate(
          notYetValidCertificatePem,
        );
        const credential = new TestMDLBuilder()
          .withUnprotectedHeader(
            new Map().set(33, new Uint8Array(notYetValidCertificate.raw)),
          )
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "Document signing certificate is not valid at the current time",
          );
        }
      });

      it("should throw MDLValidationError when MSO signature fails to verify", async () => {
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
        const credential = new TestMDLBuilder()
          .withUnprotectedHeader(
            new Map().set(
              33,
              new Uint8Array(wrongDocumentSigningCertificate.raw),
            ),
          )
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe("Signature not verified");
        } finally {
          jest.useRealTimers();
        }
      });
    });

    describe("MSO Schema", () => {
      it("should should throw MDLValidationError for MSO with AJV error", async () => {
        const mockValidator = jest
          .fn()
          .mockReturnValueOnce(true) // first call IssuerSigned (valid)
          .mockReturnValueOnce(false) as unknown as ValidateFunction; // second call MSO (invalid)
        mockValidator.errors = [
          {
            instancePath: "/path",
            message: "must be a string",
            data: 123,
            keyword: "key",
          } as unknown as ErrorObject,
        ];

        const mockAjv = {
          getSchema: jest.fn().mockReturnValue(undefined),
          addSchema: jest.fn().mockReturnThis(),
          compile: jest.fn().mockReturnValue(mockValidator),
        };

        jest
          .spyOn(ajvModule, "getAjvInstance")
          .mockReturnValue(mockAjv as never);

        const credential = new TestMDLBuilder().build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "MobileSecurityObject does not comply with schema - /path: must be a string",
          );
        }
      });

      it("should should throw MDLValidationError and default path to 'root' when instancePath is missing", async () => {
        const mockValidator = jest
          .fn()
          .mockReturnValueOnce(true) // first call IssuerSigned (valid)
          .mockReturnValueOnce(false) as unknown as ValidateFunction; // second call MSO (invalid)
        mockValidator.errors = [
          {
            instancePath: "",
            message: "must be a string",
            data: 123,
            keyword: "key",
          } as unknown as ErrorObject,
        ];

        const mockAjv = {
          getSchema: jest.fn().mockReturnValue(undefined),
          addSchema: jest.fn().mockReturnThis(),
          compile: jest.fn().mockReturnValue(mockValidator),
        };

        jest
          .spyOn(ajvModule, "getAjvInstance")
          .mockReturnValue(mockAjv as never);

        const credential = new TestMDLBuilder().build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "MobileSecurityObject does not comply with schema - root: must be a string",
          );
        }
      });

      it("should throw MDLValidationError and default to 'Unknown validation error' when message is missing", async () => {
        const mockValidator = jest
          .fn()
          .mockReturnValueOnce(true) // first call IssuerSigned (valid)
          .mockReturnValueOnce(false) as unknown as ValidateFunction; // second call MSO (invalid)
        mockValidator.errors = [
          {
            instancePath: "/path",
            message: undefined,
            data: 123,
            keyword: "key",
          } as unknown as ErrorObject,
        ];

        const mockAjv = {
          getSchema: jest.fn().mockReturnValue(undefined),
          addSchema: jest.fn().mockReturnThis(),
          compile: jest.fn().mockReturnValue(mockValidator),
        };

        jest
          .spyOn(ajvModule, "getAjvInstance")
          .mockReturnValue(mockAjv as never);

        const credential = new TestMDLBuilder().build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "MobileSecurityObject does not comply with schema - /path: Unknown validation error",
          );
        }
      });

      it("should throw MDLValidationError with empty error details when validator.errors is undefined", async () => {
        const mockValidator = jest
          .fn()
          .mockReturnValueOnce(true) // first call IssuerSigned (valid)
          .mockReturnValueOnce(false) as unknown as ValidateFunction; // second call MSO (invalid)
        mockValidator.errors = undefined;

        const mockAjv = {
          getSchema: jest.fn().mockReturnValue(undefined),
          addSchema: jest.fn().mockReturnThis(),
          compile: jest.fn().mockReturnValue(mockValidator),
        };

        jest
          .spyOn(ajvModule, "getAjvInstance")
          .mockReturnValue(mockAjv as never);

        const credential = new TestMDLBuilder().build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "MobileSecurityObject does not comply with schema - ",
          );
        }
      });
    });

    describe("Value digests", () => {
      // TODO Rewrite the following test
      // it("should throw MDLValidationError when the payload's ValueDigests is missing a digest", async () => {
      //   const credential = new TestMDLBuilder()
      //     .withoutDigest("welsh_licence")
      //     .build();
      //
      //   expect.assertions(2);
      //   try {
      //     await isValidCredential(credential);
      //   } catch (error) {
      //     expect(error).toBeInstanceOf(MDLValidationError);
      //     expect((error as Error).message).toBe(
      //       "No digest found for digest ID 20 in MSO namespace org.iso.18013.5.1.GB: 30,40",
      //     );
      //   }
      // });

      it("should throw MDLValidationError when digests don't match", async () => {
        const credential = new TestMDLBuilder()
          .withMismatchedDigest(
            "family_name",
            new Uint8Array(Buffer.from("incorrect-digest")),
          )
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "Digest mismatch for element identifier family_name with digest ID 10 in namespace org.test.namespace.2 - Expected 696e636f72726563742d646967657374 but calculated 40cb668b10272f8f5e6160d4e968d95d0c090f47c90306ebe934776ac076caba",
          );
        }
      });
    });

    describe("Device key", () => {
      it("should throw MDLValidationError when it has invalid keys", async () => {
        const credential = new TestMDLBuilder()
          .withDeviceKeyParameter(999, 1)
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "DeviceKey must contain exactly the keys [1, -1, -2, -3]",
          );
        }
      });

      it("should throw MDLValidationError when key type (1) is not EC2 (2)", async () => {
        const credential = new TestMDLBuilder()
          .withDeviceKeyParameter(1, 1)
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "DeviceKey key type (1) must be EC2 (Elliptic Curve) (2)",
          );
        }
      });

      it("should throw MDLValidationError when curve (-1) is not P-256 (1)", async () => {
        const credential = new TestMDLBuilder()
          .withDeviceKeyParameter(-1, 2)
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "DeviceKey curve (-1) must be P-256 (1)",
          );
        }
      });

      it("should throw MDLValidationError when x-coordinate (-2) is not a Uint8Array", async () => {
        const credential = new TestMDLBuilder()
          .withDeviceKeyParameter(-2, 123)
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "DeviceKey x-coordinate (-2) must be a Uint8Array",
          );
        }
      });

      it("should throw MDLValidationError when y-coordinate (-3) is not a Uint8Array", async () => {
        const credential = new TestMDLBuilder()
          .withDeviceKeyParameter(-3, "string")
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "DeviceKey y-coordinate (-3) must be a Uint8Array",
          );
        }
      });

      it("should throw MDLValidationError when it is not a valid public key", async () => {
        const credential = new TestMDLBuilder()
          .withDeviceKeyParameter(-2, new Uint8Array())
          .withDeviceKeyParameter(-3, new Uint8Array())
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe("Invalid elliptic curve key");
        }
      });
    });

    describe("Validity info", () => {
      it("should throw MDLValidationError when 'signed' is in the future", async () => {
        const credential = new TestMDLBuilder()
          .withValidityInfo({
            signed: new Tag(0, "2025-09-10T15:40:00Z"),
            validFrom: new Tag(0, "2025-09-10T15:40:00Z"),
          })
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "One or more dates are invalid - 'signed' (2025-09-10T15:40:00Z) must be in the past,'validFrom' (2025-09-10T15:40:00Z) must be in the past",
          );
        }
      });

      it("should throw MDLValidationError when 'validFrom' is before 'signed'", async () => {
        const credential = new TestMDLBuilder()
          .withValidityInfo({
            signed: new Tag(0, "2025-09-10T15:25:00Z"),
            validFrom: new Tag(0, "2025-09-10T15:20:00Z"),
          })
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "One or more dates are invalid - 'validFrom' (2026-09-10T15:20:00Z) must be equal or later than 'signed' (2025-09-10T15:25:00Z)",
          );
        }
      });

      it("should throw MDLValidationError when 'validUntil' is in the past", async () => {
        const credential = new TestMDLBuilder()
          .withValidityInfo({
            validUntil: new Tag(0, "2025-09-09T15:30:00Z"),
          })
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "One or more dates are invalid - 'validUntil' (2025-09-09T15:30:00Z) must be in the future",
          );
        }
      });

      it("should throw MDLValidationError when 'expectedUpdate' is after 'validUntil'", async () => {
        const credential = new TestMDLBuilder()
          .withValidityInfo({
            expectedUpdate: new Tag(0, "2027-01-01T00:00:00Z"),
            validUntil: new Tag(0, "2026-09-10T15:20:00Z"),
          })
          .build();

        expect.assertions(2);
        try {
          await isValidCredential(credential);
        } catch (error) {
          expect(error).toBeInstanceOf(MDLValidationError);
          expect((error as Error).message).toBe(
            "One or more dates are invalid - 'expectedUpdate' (2027-01-01T00:00:00Z) must be less than or equal to 'validUntil' (2026-09-10T15:20:00Z)",
          );
        }
      });

      it("should not throw when 'expectedUpdate' is before 'validUntil'", async () => {
        const credential = new TestMDLBuilder()
          .withValidityInfo({
            expectedUpdate: new Tag(0, "2026-01-01T00:00:00Z"),
          })
          .build();

        expect(await isValidCredential(credential)).toBe(true);
      });

      it("should not throw when 'expectedUpdate' equals 'validUntil'", async () => {
        const credential = new TestMDLBuilder()
          .withValidityInfo({
            expectedUpdate: new Tag(0, "2026-09-10T15:20:00Z"),
          })
          .build();

        expect(await isValidCredential(credential)).toBe(true);
      });
    });
  });

  it("should return true when credential is valid", async () => {
    const credential = new TestMDLBuilder().build();
    expect(await isValidCredential(credential)).toBe(true);
  });
});
