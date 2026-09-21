import { z } from "zod";
import { encodedDataTag } from "./cborTags";

export const issuerSignedSchema = z
  .object({
    nameSpaces: z
      .record(
        z.array(encodedDataTag).min(1, "must NOT have fewer than 1 items"),
      )
      .refine((obj) => Object.keys(obj).length > 0, {
        message: "must NOT have fewer than 1 properties",
      }),
    // COSE_Sign1: [protected header, unprotected header, payload, signature]
    issuerAuth: z.tuple([
      z.instanceof(Uint8Array),
      // Unprotected header. Values are constrained to bstr, which only supports a
      // single-certificate x5chain (COSE label 33). A chain with an intermediate
      // encodes x5chain as an array of bstr and will be rejected here — widen the
      // value type to z.unknown() when multi-cert chains are supported.
      z.map(z.number(), z.instanceof(Uint8Array)),
      z.instanceof(Uint8Array),
      z.instanceof(Uint8Array),
    ]),
  })
  .strict();

export type IssuerSigned = z.infer<typeof issuerSignedSchema>;
export type IssuerAuth = IssuerSigned["issuerAuth"];
export type NameSpaces = IssuerSigned["nameSpaces"];
