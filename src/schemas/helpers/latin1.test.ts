import {
  isLatin1,
  latin1String,
  latin1StringMax128,
  latin1StringMax256,
} from "./latin1";

describe("isLatin1", () => {
  it.each([
    ["ASCII", "Hello, World!"],
    ["an empty string", ""],
    ["extended Latin-1 (é)", "café"],
    ["the boundary code point U+00FF (ÿ)", "\u00ff"],
    ["U+0000", "\u0000"],
  ])("accepts %s", (_label, value) => {
    expect(isLatin1(value)).toBe(true);
  });

  it.each([
    ["U+0100 (just beyond Latin-1)", "\u0100"],
    ["the euro sign U+20AC", "€"],
    ["a CJK character", "中"],
    ["an emoji (astral plane)", "😀"],
  ])("rejects %s", (_label, value) => {
    expect(isLatin1(value)).toBe(false);
  });
});

describe("latin1String", () => {
  it("accepts a Latin-1 string", () => {
    expect(latin1String.safeParse("café").success).toBe(true);
  });

  it("rejects a non-Latin-1 string", () => {
    const result = latin1String.safeParse("€");
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe(
        "must contain only Latin1 (ISO/IEC 8859-1) characters",
      );
    }
  });
});

describe.each([
  ["latin1StringMax128", latin1StringMax128, 128],
  ["latin1StringMax256", latin1StringMax256, 256],
] as const)("%s", (_label, schema, max) => {
  it("accepts a short Latin-1 string", () => {
    expect(schema.safeParse("café").success).toBe(true);
  });

  it("accepts a single character", () => {
    expect(schema.safeParse("a").success).toBe(true);
  });

  it("accepts a string exactly at the maximum length", () => {
    expect(schema.safeParse("a".repeat(max)).success).toBe(true);
  });

  it("rejects an empty string", () => {
    expect(schema.safeParse("").success).toBe(false);
  });

  it("rejects a string one over the maximum length", () => {
    expect(schema.safeParse("a".repeat(max + 1)).success).toBe(false);
  });

  it("rejects a non-Latin-1 string", () => {
    const result = schema.safeParse("€");
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe(
        "must contain only Latin1 (ISO/IEC 8859-1) characters",
      );
    }
  });
});
