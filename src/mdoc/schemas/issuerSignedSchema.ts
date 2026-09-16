import { Tag } from "cbor2";
import { z } from "zod";

export const issuerSignedSchema = z
  .object({
    nameSpaces: z
      .record(z.array(z.unknown()).min(1, "must NOT have fewer than 1 items"))
      .refine((obj) => Object.keys(obj).length > 0, {
        message: "must NOT have fewer than 1 properties",
      }),
    issuerAuth: z.tuple([
      z.instanceof(Uint8Array, { message: "must be instance of Uint8Array" }),
      z.map(z.number(), z.instanceof(Uint8Array)),
      z.instanceof(Uint8Array, { message: "must be instance of Uint8Array" }),
      z.instanceof(Uint8Array, { message: "must be instance of Uint8Array" }),
    ]),
  })
  .strict();

export const taggedIssuerSignedSchema = z
  .object({
    nameSpaces: z
      .record(
        z.array(z.instanceof(Tag)).min(1, "must NOT have fewer than 1 items"),
      )
      .refine((obj) => Object.keys(obj).length > 0, {
        message: "must NOT have fewer than 1 properties",
      }),
    issuerAuth: z.tuple([
      z.instanceof(Uint8Array),
      z.instanceof(Map),
      z.instanceof(Uint8Array),
      z.instanceof(Uint8Array),
    ]),
  })
  .strict();

export type TaggedIssuerSigned = z.infer<typeof taggedIssuerSignedSchema>;
