import { Tag } from "cbor2";
import { TAGS } from "../constants/tags";
import { parseSchema } from "../parseSchema";
import { MdocValidationError } from "../MdocValidationError";
import { mobileSecurityObjectSchema } from "./mobileSecurityObjectSchema";

const tdate = (value: string) => new Tag(TAGS.DATE_TIME, value);

const validMso = () => ({
  version: "1.0",
  digestAlgorithm: "SHA-256",
  deviceKeyInfo: {
    deviceKey: new Map<unknown, unknown>([
      [1, 2],
      [-1, 1],
      [-2, new Uint8Array(32)],
      [-3, new Uint8Array(32)],
    ]),
    keyAuthorizations: { nameSpaces: ["org.test.namespace.1"] },
  },
  valueDigests: {
    "org.test.namespace.1": new Map<number, Uint8Array>([
      [0, new Uint8Array(32)],
    ]),
  },
  docType: "org.test.doc",
  validityInfo: {
    signed: tdate("2024-01-01T00:00:00Z"),
    validFrom: tdate("2024-01-01T00:00:00Z"),
    validUntil: tdate("2034-01-01T00:00:00Z"),
  },
  status: {
    status_list: { idx: 0, uri: "https://example.com/status/1" },
  },
});

const parseMso = (data: unknown) =>
  parseSchema(mobileSecurityObjectSchema, data, "MobileSecurityObject");

const withMso = (overrides: Record<string, unknown>) => ({
  ...validMso(),
  ...overrides,
});

describe("mobileSecurityObjectSchema", () => {
  it("accepts a valid MSO", () => {
    expect(() => parseMso(validMso())).not.toThrow();
  });

  it("rejects unknown top-level keys", () => {
    expect(() => parseMso(withMso({ unknownKey: true }))).toThrow();
  });

  it.each([
    "version",
    "digestAlgorithm",
    "deviceKeyInfo",
    "valueDigests",
    "docType",
    "validityInfo",
    "status",
  ] as const)("rejects a missing %s", (key) => {
    const { [key]: _removed, ...mso } = validMso();
    expect(() => parseMso(mso)).toThrow();
  });

  describe("docType", () => {
    it("rejects a non-string docType", () => {
      expect(() => parseMso(withMso({ docType: 1 }))).toThrow();
    });

    it("accepts a docType exactly 128 characters long", () => {
      expect(() =>
        parseMso(withMso({ docType: "a".repeat(128) })),
      ).not.toThrow();
    });

    it("rejects an empty docType", () => {
      expect(() => parseMso(withMso({ docType: "" }))).toThrow();
    });

    it("rejects a docType longer than 128 characters", () => {
      expect(() =>
        parseMso(withMso({ docType: "a".repeat(129) })),
      ).toThrow();
    });

    it("rejects a non-Latin-1 docType", () => {
      expect(() => parseMso(withMso({ docType: "€" }))).toThrow();
    });
  });

  describe("version and digestAlgorithm", () => {
    it("rejects a version other than 1.0", () => {
      expect(() => parseMso(withMso({ version: "1.1" }))).toThrow();
    });

    it.each(["SHA-384", "SHA-512"])("rejects %s", (digestAlgorithm) => {
      expect(() => parseMso(withMso({ digestAlgorithm }))).toThrow();
    });
  });

  describe("valueDigests", () => {
    it("rejects an empty record", () => {
      expect(() => parseMso(withMso({ valueDigests: {} }))).toThrow();
    });

    it("accepts multiple namespaces", () => {
      expect(() =>
        parseMso(
          withMso({
            valueDigests: {
              "org.test.namespace.1": new Map([[0, new Uint8Array(32)]]),
              "org.test.namespace.2": new Map([[0, new Uint8Array(32)]]),
            },
          }),
        ),
      ).not.toThrow();
    });

    it("rejects a plain object in place of the inner Map", () => {
      expect(() =>
        parseMso(
          withMso({
            valueDigests: { "org.test.namespace.1": { 0: new Uint8Array(32) } },
          }),
        ),
      ).toThrow();
    });

    it("rejects a non-numeric digest ID", () => {
      expect(() =>
        parseMso(
          withMso({
            valueDigests: {
              "org.test.namespace.1": new Map([["0", new Uint8Array(32)]]),
            },
          }),
        ),
      ).toThrow();
    });

    it("rejects a digest that is not bytes", () => {
      expect(() =>
        parseMso(
          withMso({
            valueDigests: { "org.test.namespace.1": new Map([[0, "abc"]]) },
          }),
        ),
      ).toThrow();
    });

    it("accepts a key exactly 256 characters long", () => {
      expect(() =>
        parseMso(
          withMso({
            valueDigests: {
              ["a".repeat(256)]: new Map([[0, new Uint8Array(32)]]),
            },
          }),
        ),
      ).not.toThrow();
    });

    it("rejects an empty key", () => {
      expect(() =>
        parseMso(
          withMso({
            valueDigests: { "": new Map([[0, new Uint8Array(32)]]) },
          }),
        ),
      ).toThrow();
    });

    it("rejects a key longer than 256 characters", () => {
      expect(() =>
        parseMso(
          withMso({
            valueDigests: {
              ["a".repeat(257)]: new Map([[0, new Uint8Array(32)]]),
            },
          }),
        ),
      ).toThrow();
    });

    it("rejects a non-Latin-1 key", () => {
      expect(() =>
        parseMso(
          withMso({
            valueDigests: { "€": new Map([[0, new Uint8Array(32)]]) },
          }),
        ),
      ).toThrow();
    });
  });

  describe("deviceKeyInfo", () => {
    it("rejects unknown keys", () => {
      expect(() =>
        parseMso(
          withMso({
            deviceKeyInfo: { ...validMso().deviceKeyInfo, unknownKey: true },
          }),
        ),
      ).toThrow();
    });

    it("rejects a missing keyAuthorizations", () => {
      expect(() =>
        parseMso(
          withMso({
            deviceKeyInfo: { deviceKey: new Map<unknown, unknown>() },
          }),
        ),
      ).toThrow();
    });

    it("rejects a missing nameSpaces in keyAuthorizations", () => {
      expect(() =>
        parseMso(
          withMso({
            deviceKeyInfo: {
              ...validMso().deviceKeyInfo,
              keyAuthorizations: {},
            },
          }),
        ),
      ).toThrow();
    });

    it("rejects a dataElements authorization", () => {
      expect(() =>
        parseMso(
          withMso({
            deviceKeyInfo: {
              ...validMso().deviceKeyInfo,
              keyAuthorizations: {
                nameSpaces: ["org.test.namespace.1"],
                dataElements: { "org.test.namespace.1": ["family_name"] },
              },
            },
          }),
        ),
      ).toThrow();
    });

    it("rejects an empty nameSpaces array", () => {
      expect(() =>
        parseMso(
          withMso({
            deviceKeyInfo: {
              ...validMso().deviceKeyInfo,
              keyAuthorizations: { nameSpaces: [] },
            },
          }),
        ),
      ).toThrow();
    });

    it("rejects a non-string namespace", () => {
      expect(() =>
        parseMso(
          withMso({
            deviceKeyInfo: {
              ...validMso().deviceKeyInfo,
              keyAuthorizations: { nameSpaces: [1] },
            },
          }),
        ),
      ).toThrow();
    });

    it("rejects duplicate nameSpaces", () => {
      expect(() =>
        parseMso(
          withMso({
            deviceKeyInfo: {
              ...validMso().deviceKeyInfo,
              keyAuthorizations: {
                nameSpaces: ["org.test.namespace.1", "org.test.namespace.1"],
              },
            },
          }),
        ),
      ).toThrow();
    });

    it("rejects a plain object in place of deviceKey", () => {
      expect(() =>
        parseMso(
          withMso({
            deviceKeyInfo: { ...validMso().deviceKeyInfo, deviceKey: {} },
          }),
        ),
      ).toThrow();
    });
  });

  describe("validityInfo", () => {
    it("accepts an optional expectedUpdate", () => {
      expect(() =>
        parseMso(
          withMso({
            validityInfo: {
              ...validMso().validityInfo,
              expectedUpdate: tdate("2030-01-01T00:00:00Z"),
            },
          }),
        ),
      ).not.toThrow();
    });

    it.each(["signed", "validFrom", "validUntil"] as const)(
      "rejects a missing %s",
      (key) => {
        const { [key]: _removed, ...validityInfo } = validMso().validityInfo;
        expect(() => parseMso(withMso({ validityInfo }))).toThrow();
      },
    );

    it.each(["signed", "validFrom", "validUntil", "expectedUpdate"])(
      "rejects an untagged %s",
      (key) => {
        expect(() =>
          parseMso(
            withMso({
              validityInfo: {
                ...validMso().validityInfo,
                [key]: "2024-01-01T00:00:00Z",
              },
            }),
          ),
        ).toThrow();
      },
    );

    it("rejects unknown keys", () => {
      expect(() =>
        parseMso(
          withMso({
            validityInfo: {
              ...validMso().validityInfo,
              unknownKey: tdate("2024-01-01T00:00:00Z"),
            },
          }),
        ),
      ).toThrow();
    });
  });

  describe("status", () => {
    it("rejects a missing status_list", () => {
      expect(() => parseMso(withMso({ status: {} }))).toThrow();
    });

    it("rejects unknown keys in status", () => {
      expect(() =>
        parseMso(
          withMso({ status: { ...validMso().status, unknownKey: true } }),
        ),
      ).toThrow();
    });

    it.each(["idx", "uri"] as const)(
      "rejects a missing %s in status_list",
      (key) => {
        const { [key]: _removed, ...statusList } =
          validMso().status.status_list;
        expect(() =>
          parseMso(withMso({ status: { status_list: statusList } })),
        ).toThrow();
      },
    );

    it("rejects a non-numeric idx", () => {
      expect(() =>
        parseMso(
          withMso({
            status: { status_list: { idx: "0", uri: "https://example.com/s" } },
          }),
        ),
      ).toThrow();
    });

    it.each([
      ["negative", -1],
      ["fractional", 1.5],
      ["above the uint32 maximum", 4294967296],
    ])("rejects an idx that is %s", (_label, idx) => {
      expect(() =>
        parseMso(
          withMso({
            status: { status_list: { idx, uri: "https://example.com/s" } },
          }),
        ),
      ).toThrow();
    });

    it.each([
      ["zero", 0],
      ["the uint32 maximum", 4294967295],
    ])("accepts an idx of %s", (_label, idx) => {
      expect(() =>
        parseMso(
          withMso({
            status: { status_list: { idx, uri: "https://example.com/s" } },
          }),
        ),
      ).not.toThrow();
    });

    it("rejects an idx that is out of range with INVALID_SCHEMA", () => {
      try {
        parseMso(
          withMso({
            status: {
              status_list: { idx: -1, uri: "https://example.com/s" },
            },
          }),
        );
        throw new Error("expected to throw");
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as MdocValidationError).code).toBe("INVALID_SCHEMA");
      }
    });

    it("rejects a non-URL uri", () => {
      expect(() =>
        parseMso(
          withMso({ status: { status_list: { idx: 0, uri: "not-a-url" } } }),
        ),
      ).toThrow();
    });

    it("accepts a uri exactly 2048 characters long", () => {
      const uri = `https://example.com/${"a".repeat(2048 - "https://example.com/".length)}`;
      expect(uri.length).toBe(2048);
      expect(() =>
        parseMso(withMso({ status: { status_list: { idx: 0, uri } } })),
      ).not.toThrow();
    });

    it("rejects a uri longer than 2048 characters", () => {
      const uri = `https://example.com/${"a".repeat(2049 - "https://example.com/".length)}`;
      expect(uri.length).toBe(2049);
      expect(() =>
        parseMso(withMso({ status: { status_list: { idx: 0, uri } } })),
      ).toThrow();
    });

    it("rejects unknown keys in status_list", () => {
      expect(() =>
        parseMso(
          withMso({
            status: {
              status_list: {
                idx: 0,
                uri: "https://example.com/s",
                unknownKey: true,
              },
            },
          }),
        ),
      ).toThrow();
    });
  });
});
