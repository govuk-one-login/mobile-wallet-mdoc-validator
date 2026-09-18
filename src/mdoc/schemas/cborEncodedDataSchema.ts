import {z} from "zod";
import {Tag} from "cbor2";
import {TAGS} from "../constants/tags";

export const cborEncodedDataTag = z
  .instanceof(Tag)
  .refine((tag) => tag.tag === TAGS.ENCODED_CBOR_DATA, {
    message: "must be tagged with 24 (encoded CBOR data)",
  })
  .refine(
    (tag): tag is Tag & { contents: Uint8Array } =>
      tag.contents instanceof Uint8Array,
    { message: "tag contents must be a Uint8Array" },
  );