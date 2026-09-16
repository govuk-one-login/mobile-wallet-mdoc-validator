import { encode, Tag } from "cbor2";
import { validateDigestIds } from "./validateDigestIds";
import { MdocValidationError } from "./MdocValidationError";
import { TAGS } from "./constants/tags";

describe("validateDigestIds", () => {
  function createTaggedItem(digestID: number, elementIdentifier: string): Tag {
    return new Tag(
      24,
      encode({
        digestID,
        random: new Uint8Array(16),
        elementIdentifier,
        elementValue: "test",
      }),
    );
  }

  it("should throw MdocValidationError when item contents is not a Uint8Array", () => {
    const namespaces = {
      "org.test.namespace": [
        new Tag(TAGS.ENCODED_CBOR_DATA, "not a Uint8Array"),
      ],
    };

    expect.assertions(2);
    try {
      validateDigestIds(namespaces);
    } catch (error) {
      expect(error).toBeInstanceOf(MdocValidationError);
      expect((error as Error).message).toBe(
        "IssuerSignedItem contents is not a Uint8Array in namespace org.test.namespace",
      );
    }
  });

  it("should throw MdocValidationError when item structure is invalid", () => {
    const namespaces = {
      "org.test.namespace": [
        new Tag(TAGS.ENCODED_CBOR_DATA, encode({ invalid: "structure" })),
      ],
    };

    expect.assertions(2);
    try {
      validateDigestIds(namespaces);
    } catch (error) {
      expect(error).toBeInstanceOf(MdocValidationError);
      expect((error as Error).message).toContain(
        "IssuerSignedItem does not comply with schema",
      );
    }
  });

  it("should not throw when digest IDs are unique", () => {
    const namespaces = {
      "org.test.namespace": [
        createTaggedItem(10, "given_name"),
        createTaggedItem(20, "family_name"),
      ],
    };

    expect(() => {
      validateDigestIds(namespaces);
    }).not.toThrow();
  });

  it("should throw MdocValidationError when digest IDs within a namespace are not unique", () => {
    const namespaces = {
      "org.test.namespace": [
        createTaggedItem(10, "given_name"),
        createTaggedItem(10, "family_name"),
      ],
    };

    expect.assertions(2);
    try {
      validateDigestIds(namespaces);
    } catch (error) {
      expect(error).toBeInstanceOf(MdocValidationError);
      expect((error as Error).message).toBe(
        "Digest IDs are not unique for namespace org.test.namespace",
      );
    }
  });
});
