import { encode, Tag } from "cbor2";
import { TAGS } from "../constants/tags";
import { parseSchema } from "../parseSchema";
import { encodedDataTag, dateTimeTag } from "./cborTags";

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

  it("rejects a string that is not a valid date", () => {
    expect(() =>
      parseDateTime(new Tag(TAGS.DATE_TIME, "not a date")),
    ).toThrow();
  });
});
