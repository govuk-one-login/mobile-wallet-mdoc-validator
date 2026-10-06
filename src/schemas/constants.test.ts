import { ELEMENT_VALUE_LIMITS } from "./constants";

describe("ELEMENT_VALUE_LIMITS", () => {
  it("locks the string bounds", () => {
    expect(ELEMENT_VALUE_LIMITS.string.minLength).toBe(1);
    expect(ELEMENT_VALUE_LIMITS.string.maxLength).toBe(150);
  });

  it("locks the number bounds to the safe-integer range", () => {
    expect(ELEMENT_VALUE_LIMITS.number.min).toBe(Number.MIN_SAFE_INTEGER);
    expect(ELEMENT_VALUE_LIMITS.number.max).toBe(Number.MAX_SAFE_INTEGER);
  });

  it("locks the Uint8Array byte-length bounds", () => {
    expect(ELEMENT_VALUE_LIMITS.uint8Array.minByteLength).toBe(1);
    expect(ELEMENT_VALUE_LIMITS.uint8Array.maxByteLength).toBe(1572864);
  });

  it("locks the collection bounds", () => {
    expect(ELEMENT_VALUE_LIMITS.collections.minLength).toBe(1);
    expect(ELEMENT_VALUE_LIMITS.collections.maxLength).toBe(256);
  });
});
