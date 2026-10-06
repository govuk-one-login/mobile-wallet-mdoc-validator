import { Tag } from "cbor2";
import { TAGS } from "../constants/tags";
import { parseSchema } from "../parseSchema";
import { MdocValidationError } from "../MdocValidationError";
import {
  primitiveScalarSchema,
  elementValueSchema,
  classifyPrimitive,
} from "./elementValueSchema";
import { ELEMENT_VALUE_LIMITS } from "./constants";

const parsePrimitive = (data: unknown) =>
  parseSchema(primitiveScalarSchema, data, "PrimitiveScalar");

const parseElementValue = (data: unknown) =>
  parseSchema(elementValueSchema, data, "ElementValue");

describe("classifyPrimitive", () => {
  it.each([
    ["a string", "x", "string"],
    ["a number", 1, "number"],
    ["a boolean", true, "boolean"],
    ["a Uint8Array", new Uint8Array([1]), "bytes"],
    ["a tag-0 date-time", new Tag(TAGS.DATE_TIME, "2024-01-01T00:00:00Z"), "date"],
    ["a tag-1004 full-date", new Tag(TAGS.FULL_DATE, "2024-01-01"), "full-date"],
  ])("classifies %s", (_label, value, expected) => {
    expect(classifyPrimitive(value)).toBe(expected);
  });

  it.each([
    ["null", null],
    ["undefined", undefined],
    ["a plain object", { a: 1 }],
    ["an array", ["x"]],
    ["a Map", new Map([["a", "b"]])],
    ["a Tag with an unsupported number", new Tag(TAGS.ENCODED_CBOR_DATA, "x")],
  ])("returns null for %s", (_label, value) => {
    expect(classifyPrimitive(value)).toBeNull();
  });
});

describe("primitiveScalarSchema", () => {
  describe("string", () => {
    it("accepts a valid Latin-1 string", () => {
      expect(() => parsePrimitive("hello")).not.toThrow();
    });

    it("accepts a single-character string", () => {
      expect(() => parsePrimitive("a")).not.toThrow();
    });

    it("accepts a 150-character string", () => {
      expect(() => parsePrimitive("a".repeat(150))).not.toThrow();
    });

    it("accepts extended Latin-1 (é)", () => {
      expect(() => parsePrimitive("café")).not.toThrow();
    });

    it("rejects an empty string", () => {
      expect(() => parsePrimitive("")).toThrow(MdocValidationError);
    });

    it("rejects a 151-character string", () => {
      expect(() => parsePrimitive("a".repeat(151))).toThrow(
        MdocValidationError,
      );
    });

    it("rejects a non-Latin-1 string", () => {
      expect(() => parsePrimitive("€")).toThrow(MdocValidationError);
    });
  });

  describe("number", () => {
    it("accepts an integer", () => {
      expect(() => parsePrimitive(42)).not.toThrow();
    });

    it("accepts zero", () => {
      expect(() => parsePrimitive(0)).not.toThrow();
    });

    it("accepts a negative integer", () => {
      expect(() => parsePrimitive(-1)).not.toThrow();
    });

    it("accepts a non-integer (float)", () => {
      expect(() => parsePrimitive(3.14)).not.toThrow();
    });

    it("accepts Number.MAX_SAFE_INTEGER", () => {
      expect(() => parsePrimitive(Number.MAX_SAFE_INTEGER)).not.toThrow();
    });

    it("accepts Number.MIN_SAFE_INTEGER", () => {
      expect(() => parsePrimitive(Number.MIN_SAFE_INTEGER)).not.toThrow();
    });

    it("rejects NaN", () => {
      expect(() => parsePrimitive(NaN)).toThrow(MdocValidationError);
    });

    it("rejects Infinity", () => {
      expect(() => parsePrimitive(Infinity)).toThrow(MdocValidationError);
    });

    it("rejects -Infinity", () => {
      expect(() => parsePrimitive(-Infinity)).toThrow(MdocValidationError);
    });

    it("rejects a number beyond MAX_SAFE_INTEGER", () => {
      expect(() => parsePrimitive(Number.MAX_SAFE_INTEGER + 1)).toThrow(
        MdocValidationError,
      );
    });

    it("rejects a number below MIN_SAFE_INTEGER", () => {
      expect(() => parsePrimitive(Number.MIN_SAFE_INTEGER - 1)).toThrow(
        MdocValidationError,
      );
    });
  });

  describe("boolean", () => {
    it("accepts true", () => {
      expect(() => parsePrimitive(true)).not.toThrow();
    });

    it("accepts false", () => {
      expect(() => parsePrimitive(false)).not.toThrow();
    });
  });

  describe("dateTimeTag", () => {
    it("accepts a Tag(0, RFC3339 UTC)", () => {
      expect(() =>
        parsePrimitive(new Tag(TAGS.DATE_TIME, "2024-01-01T00:00:00Z")),
      ).not.toThrow();
    });

    it("rejects a Tag with wrong tag number", () => {
      expect(() =>
        parsePrimitive(new Tag(TAGS.ENCODED_CBOR_DATA, "2024-01-01T00:00:00Z")),
      ).toThrow(MdocValidationError);
    });

    it("treats a plain date-shaped string as a string, not a date", () => {
      // A date-looking value that isn't wrapped in Tag 0 is validated by the
      // string branch: it passes if it is Latin-1 and within 1–150 chars.
      expect(() => parsePrimitive("2024-01-01T00:00:00Z")).not.toThrow();
    });
  });

  describe("fullDateTag", () => {
    it("accepts a Tag(1004, YYYY-MM-DD)", () => {
      expect(() =>
        parsePrimitive(new Tag(TAGS.FULL_DATE, "1980-08-15")),
      ).not.toThrow();
    });

    it("rejects a Tag(1004) with invalid contents", () => {
      expect(() =>
        parsePrimitive(new Tag(TAGS.FULL_DATE, "not a date")),
      ).toThrow(MdocValidationError);
    });
  });

  describe("Uint8Array", () => {
    it("accepts a 1-byte Uint8Array", () => {
      expect(() => parsePrimitive(new Uint8Array([1]))).not.toThrow();
    });

    it("accepts a max-size Uint8Array", () => {
      expect(() =>
        parsePrimitive(
          new Uint8Array(ELEMENT_VALUE_LIMITS.uint8Array.maxByteLength),
        ),
      ).not.toThrow();
    });

    it("rejects an empty Uint8Array", () => {
      expect(() => parsePrimitive(new Uint8Array([]))).toThrow(
        MdocValidationError,
      );
    });

    it("rejects an oversized Uint8Array", () => {
      expect(() =>
        parsePrimitive(
          new Uint8Array(ELEMENT_VALUE_LIMITS.uint8Array.maxByteLength + 1),
        ),
      ).toThrow(MdocValidationError);
    });
  });

  describe("rejection of non-primitives", () => {
    it("rejects null", () => {
      expect(() => parsePrimitive(null)).toThrow(MdocValidationError);
    });

    it("rejects undefined", () => {
      expect(() => parsePrimitive(undefined)).toThrow(MdocValidationError);
    });

    it("rejects a plain object", () => {
      expect(() => parsePrimitive({ a: 1 })).toThrow(MdocValidationError);
    });
  });
});

describe("elementValueSchema — collections", () => {
  describe("array of primitives", () => {
    it("accepts a homogeneous string array", () => {
      expect(() => parseElementValue(["a", "b", "c"])).not.toThrow();
    });

    it("accepts a homogeneous number array", () => {
      expect(() => parseElementValue([1, 2, 3])).not.toThrow();
    });

    it("accepts a homogeneous boolean array", () => {
      expect(() => parseElementValue([true, false])).not.toThrow();
    });

    it("accepts a homogeneous dateTimeTag array", () => {
      expect(() =>
        parseElementValue([
          new Tag(TAGS.DATE_TIME, "2024-01-01T00:00:00Z"),
          new Tag(TAGS.DATE_TIME, "2025-01-01T00:00:00Z"),
        ]),
      ).not.toThrow();
    });

    it("accepts a homogeneous fullDateTag array", () => {
      expect(() =>
        parseElementValue([
          new Tag(TAGS.FULL_DATE, "2024-01-01"),
          new Tag(TAGS.FULL_DATE, "2025-01-01"),
        ]),
      ).not.toThrow();
    });

    it("rejects an empty array", () => {
      expect(() => parseElementValue([])).toThrow(MdocValidationError);
    });

    it("rejects an array with more than 256 entries", () => {
      const oversized = Array.from({ length: 257 }, (_, i) => i);
      expect(() => parseElementValue(oversized)).toThrow(MdocValidationError);
    });

    it("rejects a mixed-type array", () => {
      expect(() => parseElementValue(["a", 1])).toThrow(MdocValidationError);
    });

    it("accepts exactly 256 entries", () => {
      const exact = Array.from({ length: 256 }, (_, i) => i);
      expect(() => parseElementValue(exact)).not.toThrow();
    });
  });

  describe("Map<string, primitive>", () => {
    it("accepts a homogeneous string-value map", () => {
      const map = new Map([
        ["a", "x"],
        ["b", "y"],
      ]);
      expect(() => parseElementValue(map)).not.toThrow();
    });

    it("accepts a homogeneous number-value map", () => {
      const map = new Map<string, number>([
        ["a", 1],
        ["b", 2],
      ]);
      expect(() => parseElementValue(map)).not.toThrow();
    });

    it("accepts a homogeneous date time map", () => {
      const map = new Map<string, Tag>([
        ["a", new Tag(TAGS.DATE_TIME, "2024-01-01T00:00:00Z")],
        ["b", new Tag(TAGS.DATE_TIME, "2026-01-01T00:00:00Z")],
      ]);
      expect(() => parseElementValue(map)).not.toThrow();
    });

    it("accepts a homogeneous full date map", () => {
      const map = new Map<string, Tag>([
        ["a", new Tag(TAGS.FULL_DATE, "2024-01-01")],
        ["b", new Tag(TAGS.FULL_DATE, "2026-01-01")],
      ]);
      expect(() => parseElementValue(map)).not.toThrow();
    });

    it("rejects a non-string map key", () => {
      const map = new Map<unknown, string>([[1, "x"]]);
      expect(() => parseElementValue(map)).toThrow(MdocValidationError);
    });

    it("rejects a non-Latin-1 map key", () => {
      const map = new Map([["€", "x"]]);
      expect(() => parseElementValue(map)).toThrow(MdocValidationError);
    });

    it("rejects an empty map", () => {
      expect(() => parseElementValue(new Map())).toThrow(MdocValidationError);
    });

    it("rejects an oversized map (257 entries)", () => {
      const entries = Array.from(
        { length: 257 },
        (_, i) => [i.toString(), "v"] as [string, string],
      );
      expect(() => parseElementValue(new Map(entries))).toThrow(
        MdocValidationError,
      );
    });

    it("rejects a mixed-type value map", () => {
      const map = new Map<string, unknown>([
        ["a", "x"],
        ["b", 1],
      ]);
      expect(() => parseElementValue(map)).toThrow(MdocValidationError);
    });
  });

  describe("array of maps", () => {
    it("accepts an array of homogeneous maps", () => {
      const maps = [new Map([["a", "x"]]), new Map([["b", "y"]])];
      expect(() => parseElementValue(maps)).not.toThrow();
    });

    it("rejects an empty array of maps", () => {
      expect(() => parseElementValue([] as Map<string, string>[])).toThrow(
        MdocValidationError,
      );
    });

    it("rejects an array containing an empty map", () => {
      expect(() => parseElementValue([new Map()])).toThrow(MdocValidationError);
    });

    it("rejects an oversized inner map (257 entries)", () => {
      const entries = Array.from(
        { length: 257 },
        (_, i) => [i.toString(), "v"] as [string, string],
      );
      expect(() => parseElementValue([new Map(entries)])).toThrow(
        MdocValidationError,
      );
    });

    it("rejects mixed-type values across flattened maps", () => {
      const maps = [
        new Map<string, unknown>([["a", "x"]]),
        new Map<string, unknown>([["b", 1]]),
      ];
      expect(() => parseElementValue(maps)).toThrow(MdocValidationError);
    });

    it("rejects a non-string key in an inner map", () => {
      const map = new Map<unknown, string>([[1, "x"]]);
      expect(() => parseElementValue([map])).toThrow(MdocValidationError);
    });

    it("rejects a non-Latin-1 key in an inner map", () => {
      const map = new Map([["€", "x"]]);
      expect(() => parseElementValue([map])).toThrow(MdocValidationError);
    });
  });

  describe("rejection of nested structures", () => {
    it("rejects a nested array (array containing an array)", () => {
      expect(() => parseElementValue([["a"]])).toThrow(MdocValidationError);
    });

    it("rejects a map whose value is a map", () => {
      const inner = new Map([["a", "x"]]);
      const outer = new Map<string, unknown>([["k", inner]]);
      expect(() => parseElementValue(outer)).toThrow(MdocValidationError);
    });

    it("rejects an array containing a Tag with an unsupported tag number", () => {
      expect(() =>
        parseElementValue([new Tag(TAGS.ENCODED_CBOR_DATA, "x")]),
      ).toThrow(MdocValidationError);
    });
  });

  describe("rejection of null and undefined", () => {
    it("rejects null", () => {
      expect(() => parseElementValue(null)).toThrow(MdocValidationError);
    });

    it("rejects undefined", () => {
      expect(() => parseElementValue(undefined)).toThrow(MdocValidationError);
    });
  });
});
