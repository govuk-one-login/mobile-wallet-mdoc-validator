import { Tag } from "cbor2";
import { z } from "zod";
import { dateTimeTag, fullDateTag } from "./cborTags";
import { ELEMENT_VALUE_LIMITS } from "./constants";
import { isLatin1, latin1String } from "./helpers/latin1";

const { string, number, uint8Array, collections } = ELEMENT_VALUE_LIMITS;

/**
 * A Latin-1 string of 1–150 characters.
 */
const stringScalar = latin1String
  .min(string.minLength, { message: "must not be empty" })
  .max(string.maxLength, {
    message: `must not exceed ${string.maxLength.toString()} characters`,
  });

/**
 * A number within the safe-integer range. z.number() already rejects NaN and
 * Infinity in Zod 4, and the finite min/max bounds constrain the range.
 */
const numberScalar = z.number().min(number.min).max(number.max);

const booleanScalar = z.boolean();

/**
 * A Uint8Array of 1 byte–1.5 MB.
 */
const uint8ArrayScalar = z
  .instanceof(Uint8Array)
  .refine((bytes) => bytes.byteLength >= uint8Array.minByteLength, {
    message: "must not be empty",
  })
  .refine((bytes) => bytes.byteLength <= uint8Array.maxByteLength, {
    message: `must not exceed ${uint8Array.maxByteLength.toString()} bytes`,
  });

/**
 * The five primitive DataElementValue scalars: Latin-1 string, in-range number,
 * boolean, tag-0 RFC3339 UTC date-time, tag-1004 RFC3339 full-date, and
 * bounded Uint8Array.
 */
export const primitiveScalarSchema = z.union([
  stringScalar,
  numberScalar,
  booleanScalar,
  dateTimeTag,
  fullDateTag,
  uint8ArrayScalar,
]);

/**
 * A tag used to classify a primitive value's type for homogeneity checks.
 */
type PrimitiveType =
  | "string"
  | "number"
  | "boolean"
  | "date"
  | "full-date"
  | "bytes";

/**
 * Classifies a value as one of the primitive types, or null if it is not a
 * supported primitive. Used to enforce homogeneity across collections.
 */
function classifyPrimitive(value: unknown): PrimitiveType | null {
  if (typeof value === "string") return "string";
  if (typeof value === "number") return "number";
  if (typeof value === "boolean") return "boolean";
  if (value instanceof Uint8Array) return "bytes";
  if (value instanceof Tag && value.tag === 0) return "date";
  if (value instanceof Tag && value.tag === 1004) return "full-date";
  return null;
}

/**
 * Validates that every element of the iterable is a valid primitive and that
 * all share the same primitive type. Reports issues onto the given ctx.
 */
function checkHomogeneousPrimitives(
  values: unknown[],
  ctx: z.RefinementCtx,
): void {
  let expectedType: PrimitiveType | null = null;

  for (const value of values) {
    const result = primitiveScalarSchema.safeParse(value);
    if (!result.success) {
      ctx.addIssue({
        code: "custom",
        message: "all values must be valid primitives",
      });
      return;
    }

    const type = classifyPrimitive(value);
    if (expectedType === null) {
      expectedType = type;
    } else if (type !== expectedType) {
      ctx.addIssue({
        code: "custom",
        message: "all values must be the same primitive type",
      });
      return;
    }
  }
}

/**
 * An array of homogeneous primitives: non-empty, ≤256 entries, single type.
 */
const primitiveArraySchema = z
  .array(z.unknown())
  .min(collections.minLength, { message: "must not be empty" })
  .max(collections.maxLength, {
    message: `must not exceed ${collections.maxLength.toString()} entries`,
  })
  .superRefine((values, ctx) => {
    checkHomogeneousPrimitives(values, ctx);
  });

/**
 * A Map<string, primitive> with Latin-1 string keys: non-empty, ≤256 entries,
 * homogeneous values.
 */
const primitiveMapSchema = z
  .map(z.unknown(), z.unknown())
  .superRefine((map, ctx) => {
    if (map.size < collections.minLength) {
      ctx.addIssue({ code: "custom", message: "must not be empty" });
      return;
    }
    if (map.size > collections.maxLength) {
      ctx.addIssue({
        code: "custom",
        message: `must not exceed ${collections.maxLength.toString()} entries`,
      });
      return;
    }

    for (const key of map.keys()) {
      if (typeof key !== "string") {
        ctx.addIssue({ code: "custom", message: "all keys must be strings" });
        return;
      }
      if (!isLatin1(key)) {
        ctx.addIssue({
          code: "custom",
          message: "keys must contain only Latin1 (ISO/IEC 8859-1) characters",
        });
        return;
      }
    }

    checkHomogeneousPrimitives([...map.values()], ctx);
  });

/**
 * An array of primitive maps: non-empty, ≤256 entries; each inner map
 * non-empty and ≤256 with Latin-1 string keys; and the values flattened across
 * all maps must be homogeneous.
 */
const mapArraySchema = z
  .array(z.map(z.unknown(), z.unknown()))
  .min(collections.minLength, { message: "must not be empty" })
  .max(collections.maxLength, {
    message: `must not exceed ${collections.maxLength.toString()} entries`,
  })
  .superRefine((maps, ctx) => {
    const flattenedValues: unknown[] = [];

    for (const map of maps) {
      if (map.size < collections.minLength) {
        ctx.addIssue({ code: "custom", message: "must not be empty" });
        return;
      }
      if (map.size > collections.maxLength) {
        ctx.addIssue({
          code: "custom",
          message: `must not exceed ${collections.maxLength.toString()} entries`,
        });
        return;
      }

      for (const key of map.keys()) {
        if (typeof key !== "string") {
          ctx.addIssue({ code: "custom", message: "all keys must be strings" });
          return;
        }
        if (!isLatin1(key)) {
          ctx.addIssue({
            code: "custom",
            message: "keys must contain only Latin1 (ISO/IEC 8859-1) characters",
          });
          return;
        }
      }

      flattenedValues.push(...map.values());
    }

    checkHomogeneousPrimitives(flattenedValues, ctx);
  });

/**
 * The DataElementValue schema: a primitive scalar, an array of primitives, a
 * Map<string, primitive>, or an array of such maps. Nested arrays and
 * maps-of-maps are rejected because their values would fail the primitive
 * homogeneity check. null and undefined are rejected (not members of the
 * union).
 */
export const elementValueSchema = z.union([
  primitiveScalarSchema,
  primitiveArraySchema,
  primitiveMapSchema,
  mapArraySchema,
]);

export type ElementValue = z.infer<typeof elementValueSchema>;
