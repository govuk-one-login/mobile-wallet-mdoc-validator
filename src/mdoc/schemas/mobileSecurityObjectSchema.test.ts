import { Tag } from "cbor2";
import { TAGS } from "../constants/tags";
import { parseSchema } from "../parseSchema";
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
    "org.test.namespace.1": new Map<number, Uint8Array>([[0, new Uint8Array(32)]]),
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
  ])("rejects a missing %s", (key) => {
    const mso: Record<string, unknown> = validMso();
    delete mso[key];
    expect(() => parseMso(mso)).toThrow();
  });

  it("rejects a non-string docType", () => {
    expect(() => parseMso(withMso({ docType: 1 }))).toThrow();
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
            valueDigests: {"org.test.namespace.1": { 0: new Uint8Array(32) } },
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

    it.each(["signed", "validFrom", "validUntil"])(
      "rejects a missing %s",
      (key) => {
        const validityInfo: Record<string, unknown> = validMso().validityInfo;
        delete validityInfo[key];
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
        parseMso(withMso({ status: { ...validMso().status, unknownKey: true } })),
      ).toThrow();
    });

    it.each(["idx", "uri"])("rejects a missing %s in status_list", (key) => {
      const statusList: Record<string, unknown> = {
        ...validMso().status.status_list,
      };
      delete statusList[key];
      expect(() =>
        parseMso(withMso({ status: { status_list: statusList } })),
      ).toThrow();
    });

    it("rejects a non-numeric idx", () => {
      expect(() =>
        parseMso(
          withMso({
            status: { status_list: { idx: "0", uri: "https://example.com/s" } },
          }),
        ),
      ).toThrow();
    });

    it("rejects a non-URL uri", () => {
      expect(() =>
        parseMso(
          withMso({ status: { status_list: { idx: 0, uri: "not-a-url" } } }),
        ),
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