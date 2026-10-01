import { Tag } from "cbor2";
import { z } from "zod";
import { TAGS } from "../constants/tags";

export const encodedDataTag = z
  .instanceof(Tag)
  .refine((tag) => tag.tag === TAGS.ENCODED_CBOR_DATA, {
    message: "must be tagged with 24 (encoded CBOR data)",
  })
  .refine(
    (tag): tag is Tag & { contents: Uint8Array } =>
      tag.contents instanceof Uint8Array,
    { message: "tag contents must be a Uint8Array" },
  );

export const dateTimeTag = z
  .instanceof(Tag)
  .refine((tag) => tag.tag === TAGS.DATE_TIME, {
    message: "must be tagged with 0 (date-time)",
  })
  .refine(
    (tag): tag is Tag & { contents: string } =>
      typeof tag.contents === "string",
    { message: "tag contents must be a string" },
  )
  .refine(
    (tag) =>
      z.iso.datetime({ precision: 0 }).length(20).safeParse(tag.contents)
        .success,
    {
      message:
        "tag contents must be an RFC 3339 UTC date-time (YYYY-MM-DDTHH:MM:SSZ)",
    },
  );
