import { errorMessage, MdocValidationError } from "./MdocValidationError";

describe("MdocValidationError", () => {
  it("defaults the code to VALIDATION_FAILED", () => {
    const error = new MdocValidationError("boom");
    expect(error.message).toBe("boom");
    expect(error.code).toBe("VALIDATION_FAILED");
    expect(error.name).toBe("MdocValidationError");
    expect(error).toBeInstanceOf(Error);
  });

  it("uses the provided code", () => {
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
