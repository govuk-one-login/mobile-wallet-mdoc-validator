import { encode, Tag } from "cbor2";
import { TAGS } from "../constants/tags";
import { parseSchema } from "../parseSchema";
import { issuerSignedSchema } from "./issuerSignedSchema";

const validIssuerSignedItem = () => ({
  digestID: 0,
  elementIdentifier: "family_name",
  elementValue: "Doe",
  random: new Uint8Array(16),
});

const taggedIssuerSignedItem = () =>
  new Tag(TAGS.ENCODED_CBOR_DATA, encode(validIssuerSignedItem()));

const validIssuerSigned = () => ({
  nameSpaces: { "org.test.namespace.1": [taggedIssuerSignedItem()] },
  issuerAuth: [
    new Uint8Array([1]),
    new Map([[33, new Uint8Array([2])]]),
    new Uint8Array([3]),
    new Uint8Array([4]),
  ],
});

const parseIssuerSigned = (data: unknown) =>
  parseSchema(issuerSignedSchema, data, "IssuerSigned");

describe("issuerSignedSchema", () => {
  it("accepts a valid structure", () => {
    expect(() => parseIssuerSigned(validIssuerSigned())).not.toThrow();
  });

  it("rejects unknown top-level keys", () => {
    expect(() =>
      parseIssuerSigned({ ...validIssuerSigned(), unknownKey: true }),
    ).toThrow();
  });

  describe("nameSpaces", () => {
    it("rejects an empty map", () => {
      expect(() =>
        parseIssuerSigned({ ...validIssuerSigned(), nameSpaces: {} }),
      ).toThrow();
    });

    it("rejects a namespace with no items", () => {
      expect(() =>
        parseIssuerSigned({
          ...validIssuerSigned(),
          nameSpaces: { "org.test.namespace.2": [] },
        }),
      ).toThrow();
    });

    it("accepts multiple namespaces", () => {
      expect(() =>
        parseIssuerSigned({
          ...validIssuerSigned(),
          nameSpaces: {
            "org.test.namespace.1": [taggedIssuerSignedItem()],
            "org.test.namespace.2": [taggedIssuerSignedItem()],
          },
        }),
      ).not.toThrow();
    });
  });

  describe("issuerAuth", () => {
    it("rejects a tuple of the wrong length", () => {
      expect(() =>
        parseIssuerSigned({
          ...validIssuerSigned(),
          issuerAuth: [new Uint8Array([1]), new Map(), new Uint8Array([3])],
        }),
      ).toThrow();
    });

    it("rejects an array-valued x5chain", () => {
      expect(() =>
        parseIssuerSigned({
          ...validIssuerSigned(),
          issuerAuth: [
            new Uint8Array([1]),
            new Map([[33, [new Uint8Array([2]), new Uint8Array([3])]]]),
            new Uint8Array([3]),
            new Uint8Array([4]),
          ],
        }),
      ).toThrow();
    });
  });
});
