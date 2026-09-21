import { z } from "zod";
import { MdocValidationError } from "./MdocValidationError";

export function parseSchema<T>(
  schema: z.ZodType<T, z.ZodTypeDef, unknown>,
  data: unknown,
  label: string,
): T {
  const result = schema.safeParse(data);
  if (result.success) return result.data;

  const errorDetails = result.error.issues
    .map((issue) => `${issue.path.join("/") || "root"}: ${issue.message}`)
    .join("; ");

  throw new MdocValidationError(
    `${label} does not comply with schema - ${errorDetails}`,
    "INVALID_SCHEMA",
  );
}
