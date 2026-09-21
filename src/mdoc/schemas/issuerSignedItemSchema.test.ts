import { parseSchema } from "../parseSchema";
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

    // Accepted: CBOR permits zero-length text strings and the spec's CDDL
    // (DataElementIdentifier = tstr) sets no minimum length.
    it("accepts an empty string", () => {
      expect(() =>
        parseIssuerSignedItem({
          ...validIssuerSignedItem(),
          elementIdentifier: "",
        }),
      ).not.toThrow();
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

    // The spec allows any value here (DataElementValue = any), including CBOR null,
    // so null is accepted. CBOR undefined decodes to JS undefined and is rejected
    // as missing — a deliberate narrowing, since no issuer should sign an absent value.
    it("accepts null", () => {
      expect(() =>
        parseIssuerSignedItem({ ...validIssuerSignedItem(), elementValue: null }),
      ).not.toThrow();
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

    it.each(["digestID", "elementIdentifier", "elementValue", "random"])(
      "rejects a missing %s",
      (key) => {
        const item: Record<string, unknown> = validIssuerSignedItem();
        delete item[key];
        expect(() => parseIssuerSignedItem(item)).toThrow();
      },
    );
  });
});