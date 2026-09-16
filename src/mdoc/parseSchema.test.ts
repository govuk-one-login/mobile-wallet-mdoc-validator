import { z } from "zod";
import { parseSchema } from "./parseSchema";
import { MdocValidationError } from "./MdocValidationError";

describe("parseSchema", () => {
  const testSchema = z.object({ name: z.string() }).strict();

  it("should throw MdocValidationError with path and message", () => {
    expect.assertions(2);
    try {
      parseSchema(testSchema, { name: 123 }, "TestLabel");
    } catch (error) {
      expect(error).toBeInstanceOf(MdocValidationError);
      expect((error as Error).message).toBe(
        "TestLabel does not comply with schema - name: Expected string, received number",
      );
    }
  });

  it("should default path to 'root' when path is empty", () => {
    expect.assertions(2);
    try {
      parseSchema(testSchema, "not an object", "TestLabel");
    } catch (error) {
      expect(error).toBeInstanceOf(MdocValidationError);
      expect((error as Error).message).toMatch(
        "TestLabel does not comply with schema - root: Expected object, received string",
      );
    }
  });

  it("should return parsed data when valid", () => {
    const result = parseSchema(testSchema, { name: "Alice" }, "TestLabel");
    expect(result).toEqual({ name: "Alice" });
  });
});
