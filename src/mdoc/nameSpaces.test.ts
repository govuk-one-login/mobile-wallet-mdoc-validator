import { encode, Tag } from "cbor2";
import { TAGS } from "./constants/tags";
import { MdocValidationError } from "./MdocValidationError";
import { validateNamespaces } from "./nameSpaces";
import type { NameSpaces } from "./schemas/issuerSignedSchema";

const taggedIssuerSignedItem = (digestID: number, elementIdentifier: string) =>
  new Tag(
    TAGS.ENCODED_CBOR_DATA,
    encode({
      digestID,
      elementIdentifier,
      elementValue: "value",
      random: new Uint8Array(16),
    }),
  );

const nameSpaces = (value: Record<string, Tag[]>) =>
  value as unknown as NameSpaces;

describe("validateNamespaces", () => {
  it("accepts unique digest IDs and element identifiers", () => {
    expect(() =>
      validateNamespaces(
        nameSpaces({
          "org.test.namespace.1": [
            taggedIssuerSignedItem(0, "family_name"),
            taggedIssuerSignedItem(1, "given_name"),
          ],
        }),
      ),
    ).not.toThrow();
  });

  describe("digest IDs", () => {
    it("rejects duplicates within a namespace", () => {
      expect(() =>
        validateNamespaces(
          nameSpaces({
            "org.test.namespace.1": [
              taggedIssuerSignedItem(0, "family_name"),
              taggedIssuerSignedItem(0, "given_name"),
            ],
          }),
        ),
      ).toThrow(MdocValidationError);
    });

    it("allows the same digest ID in different namespaces", () => {
      expect(() =>
        validateNamespaces(
          nameSpaces({
            "org.test.namespace.1": [taggedIssuerSignedItem(0, "family_name")],
            "org.test.namespace.2": [taggedIssuerSignedItem(0, "title")],
          }),
        ),
      ).not.toThrow();
    });

    it("names the duplicate ID and its namespace in the message", () => {
      expect(() =>
        validateNamespaces(
          nameSpaces({
            "org.test.namespace.1": [taggedIssuerSignedItem(0, "family_name")],
            "org.test.namespace.2": [
              taggedIssuerSignedItem(7, "title"),
              taggedIssuerSignedItem(7, "portrait"),
            ],
          }),
        ),
      ).toThrow("Duplicate digest ID 7 in namespace org.test.namespace.2");
    });
  });

  describe("element identifiers", () => {
    it("rejects duplicates within a namespace", () => {
      expect(() =>
        validateNamespaces(
          nameSpaces({
            "org.test.namespace.1": [
              taggedIssuerSignedItem(0, "family_name"),
              taggedIssuerSignedItem(1, "family_name"),
            ],
          }),
        ),
      ).toThrow(MdocValidationError);
    });

    it("allows the same element identifier in different namespaces", () => {
      expect(() =>
        validateNamespaces(
          nameSpaces({
            "org.test.namespace.1": [taggedIssuerSignedItem(0, "issue_date")],
            "org.test.namespace.2": [taggedIssuerSignedItem(1, "issue_date")],
          }),
        ),
      ).not.toThrow();
    });

    it("names the duplicate identifier and its namespace in the message", () => {
      expect(() =>
        validateNamespaces(
          nameSpaces({
            "org.test.namespace.1": [taggedIssuerSignedItem(0, "family_name")],
            "org.test.namespace.2": [
              taggedIssuerSignedItem(1, "portrait"),
              taggedIssuerSignedItem(2, "portrait"),
            ],
          }),
        ),
      ).toThrow(
        "Duplicate element identifier portrait in namespace org.test.namespace.2",
      );
    });
  });

  describe("item parsing", () => {
    it("rejects an item that does not match the schema", () => {
      expect(() =>
        validateNamespaces(
          nameSpaces({
            "org.test.namespace.1": [
              new Tag(TAGS.ENCODED_CBOR_DATA, encode({ digestID: 0 })),
            ],
          }),
        ),
      ).toThrow(/IssuerSignedItem does not comply with schema/);
    });

    it("rejects item contents that are not valid CBOR", () => {
      expect(() =>
        validateNamespaces(
          nameSpaces({
            "org.test.namespace.1": [
              new Tag(TAGS.ENCODED_CBOR_DATA, new Uint8Array([0xa1, 0x01])),
            ],
          }),
        ),
      ).toThrow(/IssuerSignedItem is not valid CBOR/);
    });
  });
});