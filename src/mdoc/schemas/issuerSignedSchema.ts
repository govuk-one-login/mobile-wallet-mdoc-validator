import { Tag } from "cbor2";
import { z } from "zod";
import { TAGS } from "../constants/tags";

export const issuerSignedItemSchema = z
  .object({
    digestID: z
      .number()
      .int()
      .nonnegative()
      .lt(2 ** 31),
    elementIdentifier: z.string(),
    elementValue: z.custom(
      (val) => val !== undefined,
      "elementValue is required",
    ),
    random: z.instanceof(Uint8Array).refine((r) => r.length >= 16, {
      message: "random must be at least 16 bytes",
    }),
  })
  .strict();

const cborEncodedDataTag = z
  .instanceof(Tag)
  .refine((tag) => tag.tag === TAGS.ENCODED_CBOR_DATA, {
    message: "must be tagged with 24 (encoded CBOR data)",
  });

export const issuerSignedSchema = z
  .object({
    nameSpaces: z
      .record(
        z.array(cborEncodedDataTag).min(1, "must NOT have fewer than 1 items"),
      )
      .refine((obj) => Object.keys(obj).length > 0, {
        message: "must NOT have fewer than 1 properties",
      }),
    issuerAuth: z.tuple([
      z.instanceof(Uint8Array),
      z.map(z.number(), z.instanceof(Uint8Array)),
      z.instanceof(Uint8Array),
      z.instanceof(Uint8Array),
    ]),
  })
  .strict();

export type IssuerSigned = z.infer<typeof issuerSignedSchema>;
export type IssuerSignedItem = z.infer<typeof issuerSignedItemSchema>;
export type IssuerAuth = IssuerSigned["issuerAuth"];
