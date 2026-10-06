import { encode, Tag } from "cbor2";
import { TAGS } from "../constants/tags";
import { parseSchema } from "../parseSchema";
import { encodedDataTag, dateTimeTag, fullDateTag } from "./cborTags";

const parseEncodedData = (data: unknown) =>
  parseSchema(encodedDataTag, data, "EncodedCborData");

const parseDateTime = (data: unknown) =>
  parseSchema(dateTimeTag, data, "DateTime");

describe("encodedDataTag", () => {
  it("accepts a tag 24 wrapping bytes", () => {
    expect(() =>
      parseEncodedData(new Tag(TAGS.ENCODED_CBOR_DATA, encode({ a: 1 }))),
    ).not.toThrow();
  });

  it("rejects a different tag number", () => {
    expect(() =>
      parseEncodedData(new Tag(TAGS.DATE_TIME, encode({ a: 1 }))),
    ).toThrow();
  });

  it.each([
    ["a string", "not bytes"],
    ["a number", 42],
    ["an object", { a: 1 }],
    ["null", null],
  ])("rejects contents that are %s", (_label, contents) => {
    expect(() =>
      parseEncodedData(new Tag(TAGS.ENCODED_CBOR_DATA, contents)),
    ).toThrow();
  });

  it("rejects a value that is not a Tag", () => {
    expect(() => parseEncodedData(encode({ a: 1 }))).toThrow();
  });
});

describe("dateTimeTag", () => {
  it("accepts a tag 0 wrapping a string", () => {
    expect(() =>
      parseDateTime(new Tag(TAGS.DATE_TIME, "2024-01-01T00:00:00Z")),
    ).not.toThrow();
  });

  it("rejects a different tag number", () => {
    expect(() =>
      parseDateTime(new Tag(TAGS.ENCODED_CBOR_DATA, "2024-01-01T00:00:00Z")),
    ).toThrow();
  });

  it.each([
    ["a number", 1704067200],
    ["bytes", new Uint8Array([1])],
    ["null", null],
  ])("rejects contents that are %s", (_label, contents) => {
    expect(() => parseDateTime(new Tag(TAGS.DATE_TIME, contents))).toThrow();
  });

  it("rejects a value that is not a Tag", () => {
    expect(() => parseDateTime("2024-01-01T00:00:00Z")).toThrow();
  });

  it("accepts the canonical UTC form YYYY-MM-DDTHH:MM:SSZ", () => {
    expect(() =>
      parseDateTime(new Tag(TAGS.DATE_TIME, "2024-01-01T00:00:00Z")),
    ).not.toThrow();
  });

  it.each([
    ["free text", "not a date"],
    ["an empty string", ""],
    ["date only", "2025-09-10"],
    ["a slash format", "10/09/2025"],
    ["a space separator instead of T", "2025-09-10 14:30:00Z"],
    ["fractional seconds", "2025-09-10T14:30:00.123Z"],
    ["a non-UTC offset", "2025-09-10T14:30:00+01:00"],
    ["a missing Z designator", "2025-09-10T14:30:00"],
    ["a lowercase z", "2025-09-10T14:30:00z"],
    ["trailing characters", "2025-09-10T14:30:00Z "],
  ])("rejects %s", (_label, contents) => {
    expect(() => parseDateTime(new Tag(TAGS.DATE_TIME, contents))).toThrow();
  });
});

const parseFullDate = (data: unknown) =>
  parseSchema(fullDateTag, data, "FullDate");

describe("fullDateTag", () => {
  it("accepts a tag 1004 wrapping a full-date string", () => {
    expect(() =>
      parseFullDate(new Tag(TAGS.FULL_DATE, "1980-08-15")),
    ).not.toThrow();
  });

  it("rejects a different tag number", () => {
    expect(() =>
      parseFullDate(new Tag(TAGS.DATE_TIME, "1980-08-15")),
    ).toThrow();
  });

  it.each([
    ["a number", 1704067200],
    ["bytes", new Uint8Array([1])],
    ["null", null],
  ])("rejects contents that are %s", (_label, contents) => {
    expect(() => parseFullDate(new Tag(TAGS.FULL_DATE, contents))).toThrow();
  });

  it("rejects a value that is not a Tag", () => {
    expect(() => parseFullDate("1980-08-15")).toThrow();
  });

  it.each([
    ["free text", "not a date"],
    ["an empty string", ""],
    ["a date-time (not date-only)", "2025-09-10T14:30:00Z"],
    ["a slash format", "10/09/2025"],
    ["trailing characters", "2025-09-10 "],
    ["year only", "2025"],
  ])("rejects string content that is %s", (_label, contents) => {
    expect(() => parseFullDate(new Tag(TAGS.FULL_DATE, contents))).toThrow();
  });
});
