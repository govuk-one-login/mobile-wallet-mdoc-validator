import { z } from "zod";
import { MdocValidationError } from "./MdocValidationError";
import { parseSchema } from "./parseSchema";

const schema = z.object({ id: z.number() }).strict();

describe("parseSchema", () => {
  it("returns the parsed data when valid", () => {
    expect(parseSchema(schema, { id: 1 }, "Thing")).toEqual({ id: 1 });
  });

  it("throws an MdocValidationError with INVALID_SCHEMA when invalid", () => {
    expect.assertions(2);
    try {
      parseSchema(schema, { id: "one" }, "Thing");
    } catch (error) {
      expect(error).toBeInstanceOf(MdocValidationError);
      expect((error as MdocValidationError).code).toBe("INVALID_SCHEMA");
    }
  });

  it("includes the label in the message", () => {
    expect(() => parseSchema(schema, {}, "Thing")).toThrow(/Thing/);
  });

  it("includes the failing path in the message", () => {
    expect(() => parseSchema(schema, { id: "one" }, "Thing")).toThrow(/id/);
  });

  it("reports the root path when the value itself is wrong", () => {
    expect(() => parseSchema(schema, "not an object", "Thing")).toThrow(/root/);
  });

  it("reports every issue, not just the first", () => {
    const multi = z.object({ a: z.number(), b: z.number() }).strict();
    const fn = () => parseSchema(multi, { a: "x", b: "y" }, "Thing");

    expect(fn).toThrow(/a:/);
    expect(fn).toThrow(/b:/);
  });
});
