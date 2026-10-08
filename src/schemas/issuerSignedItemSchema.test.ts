import { parseSchema } from "../parseSchema";
import { MdocValidationError } from "../MdocValidationError";
import { issuerSignedItemSchema } from "./issuerSignedItemSchema";

const validIssuerSignedItem = () => ({
  digestID: 0,
  elementIdentifier: "family_name",
  elementValue: "Doe",
  random: new Uint8Array(16),
});

const parseIssuerSignedItem = (data: unknown) =>
  parseSchema(issuerSignedItemSchema, data, "IssuerSignedItem");

describe("issuerSignedItemSchema", () => {
  it("accepts a valid item", () => {
    expect(() => parseIssuerSignedItem(validIssuerSignedItem())).not.toThrow();
  });

  describe("digestID", () => {
    it.each([
      ["negative", -1],
      ["non-integer", 1.5],
      ["at 2^31", 2 ** 31],
      ["not a number", "0"],
    ])("rejects %s", (_label, digestID) => {
      expect(() =>
        parseIssuerSignedItem({ ...validIssuerSignedItem(), digestID }),
      ).toThrow();
    });

    it("accepts zero", () => {
      expect(() =>
        parseIssuerSignedItem({ ...validIssuerSignedItem(), digestID: 0 }),
      ).not.toThrow();
    });

    it("accepts the maximum permitted value", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          digestID: 2 ** 31 - 1,
        }),
      ).not.toThrow();
    });
  });

  describe("elementIdentifier", () => {
    it("rejects a non-string", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementIdentifier: 1,
        }),
      ).toThrow();
    });

    it("accepts an identifier exactly 256 characters long", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementIdentifier: "a".repeat(256),
        }),
      ).not.toThrow();
    });

    it("rejects an empty string", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementIdentifier: "",
        }),
      ).toThrow();
    });

    it("rejects an identifier longer than 256 characters", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementIdentifier: "a".repeat(257),
        }),
      ).toThrow();
    });

    it("rejects a non-Latin-1 identifier with INVALID_SCHEMA", () => {
      try {
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementIdentifier: "€",
        });
        throw new Error("expected to throw");
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as MdocValidationError).code).toBe("INVALID_SCHEMA");
      }
    });
  });

  describe("elementValue", () => {
    it("rejects an explicitly undefined value", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementValue: undefined,
        }),
      ).toThrow();
    });

    it("rejects null", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementValue: null,
        }),
      ).toThrow();
    });

    it("accepts a valid primitive string", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementValue: "Doe",
        }),
      ).not.toThrow();
    });

    it("accepts a valid homogeneous collection", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementValue: ["a", "b", "c"],
        }),
      ).not.toThrow();
    });

    it("rejects a malformed primitive with INVALID_SCHEMA", () => {
      try {
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementValue: "€",
        });
        throw new Error("expected to throw");
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as MdocValidationError).code).toBe("INVALID_SCHEMA");
      }
    });

    it("rejects a malformed collection with INVALID_SCHEMA", () => {
      try {
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementValue: ["a", 1],
        });
        throw new Error("expected to throw");
      } catch (error) {
        expect(error).toBeInstanceOf(MdocValidationError);
        expect((error as MdocValidationError).code).toBe("INVALID_SCHEMA");
      }
    });
  });

  describe("random", () => {
    it("rejects fewer than 16 bytes", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          random: new Uint8Array(15),
        }),
      ).toThrow();
    });

    it("rejects a non-Uint8Array", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          random: "0".repeat(16),
        }),
      ).toThrow();
    });

    it("accepts exactly 16 bytes", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          random: new Uint8Array(16),
        }),
      ).not.toThrow();
    });

    it("accepts more than 16 bytes", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          random: new Uint8Array(32),
        }),
      ).not.toThrow();
    });
  });

  describe("strictness", () => {
    it("rejects unknown keys", () => {
      expect(() =>
        parseIssuerSignedItem({ ...validIssuerSignedItem(), unknownKey: true }),
      ).toThrow();
    });

    it.each([
      "digestID",
      "elementIdentifier",
      "elementValue",
      "random",
    ] as const)("rejects a missing %s", (key) => {
      const { [key]: _removed, ...item } = validIssuerSignedItem();
      expect(() => parseIssuerSignedItem(item)).toThrow();
    });
  });
});
