import { encode, getEncoded, Tag } from "cbor2";
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

  it("preserves the original encoded bytes of a decoded value (saveOriginal)", () => {
    // Build a tag-24 item (the IssuerSignedItemBytes shape) whose inner map is
    // non-canonically encoded: the value 1 is written in the two-byte form
    // (0x18 0x01) instead of the minimal single-byte form (0x01). getEncoded
    // returns the original bytes exactly as received — the property the MSO
    // digest verification relies on, so the digest is taken over the issuer's
    // actual signed bytes rather than depending on re-encode fidelity.
    //
    // 0xd8 0x18            tag(24)
    //   0x45               bstr length 5 (the inner CBOR)
    //     0xa1             map(1)
    //       0x61 0x61      text "a"
    //       0x18 0x01      unsigned 1, non-minimal two-byte form
    const original = new Uint8Array([
      0xd8, 0x18, 0x45, 0xa1, 0x61, 0x61, 0x18, 0x01,
    ]);
    const decoded = decodeCbor(original, "Thing");

    expect(decoded).toBeInstanceOf(Tag);
    // The preserved original bytes are byte-identical to the input, including
    // the non-minimal integer encoding. This is what gets hashed for digest
    // verification, so a non-canonically encoded (but validly signed) item
    // still matches its MSO digest instead of being re-encoded first.
    expect(getEncoded(decoded)).toEqual(original);
  });
});
