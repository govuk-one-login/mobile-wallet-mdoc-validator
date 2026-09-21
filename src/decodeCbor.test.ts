import { encode, Tag } from "cbor2";
import { decodeCbor } from "./decodeCbor";
import { MdocValidationError } from "./MdocValidationError";

describe("decodeCbor", () => {
  it("decodes valid CBOR", () => {
    expect(decodeCbor(encode({ a: 1 }), "Thing")).toEqual({ a: 1 });
  });

  it("throws an MdocValidationError with INVALID_CBOR on malformed input", () => {
    expect.assertions(2);
    try {
      decodeCbor(new Uint8Array([0xa1, 0x01]), "Thing");
    } catch (error) {
      expect(error).toBeInstanceOf(MdocValidationError);
      expect((error as MdocValidationError).code).toBe("INVALID_CBOR");
    }
  });

  it("includes the label in the error message", () => {
    expect(() => decodeCbor(new Uint8Array([0xa1, 0x01]), "Thing")).toThrow(
      /Thing/,
    );
  });

  it("decodes tag 0 as a Tag rather than a Date", () => {
    const decoded = decodeCbor(
      encode(new Tag(0, "2024-01-01T00:00:00Z")),
      "Thing",
    );

    expect(decoded).toBeInstanceOf(Tag);
    expect((decoded as Tag).tag).toBe(0);
    expect((decoded as Tag).contents).toBe("2024-01-01T00:00:00Z");
  });

  it("rejects a map with duplicate keys", () => {
    // { "a": 1, "a": 2 }: a two-pair map where both keys are "a"
    const bytes = new Uint8Array([0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02]);
    expect(() => decodeCbor(bytes, "Thing")).toThrow(MdocValidationError);
  });
});
