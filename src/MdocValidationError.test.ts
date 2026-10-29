import { errorMessage, MdocValidationError } from "./MdocValidationError";

describe("MdocValidationError", () => {
  it("sets message, name, and code (defaulting when omitted)", () => {
    const defaulted = new MdocValidationError("boom");
    expect(defaulted.message).toBe("boom");
    expect(defaulted.name).toBe("MdocValidationError");
    expect(defaulted).toBeInstanceOf(Error);
    expect(defaulted.code).toBe("VALIDATION_FAILED");

    expect(new MdocValidationError("boom", "INVALID_CBOR").code).toBe(
      "INVALID_CBOR",
    );
  });
});

describe("errorMessage", () => {
  it("returns the message of an Error", () => {
    expect(errorMessage(new Error("failed"))).toBe("failed");
  });

  it("stringifies a non-Error value", () => {
    expect(errorMessage("just a string")).toBe("just a string");
    expect(errorMessage(42)).toBe("42");
  });
});
