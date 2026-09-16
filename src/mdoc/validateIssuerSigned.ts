import { ZodError } from "zod";
import { IssuerSigned } from "./types/issuerSigned";
import { issuerSignedSchema } from "./schemas/issuerSignedSchema";
import { MdocValidationError } from "./MdocValidationError";

export function validateIssuerSignedSchema(issuerSigned: IssuerSigned): void {
  try {
    issuerSignedSchema.parse(issuerSigned);
  } catch (error) {
    if (error instanceof ZodError) {
      const errorDetails = error.issues
        .map((issue) => `${issue.path.join("/") || "root"}: ${issue.message}`)
        .join("; ");

      throw new MdocValidationError(
        `IssuerSigned does not comply with schema - ${errorDetails}`,
        "INVALID_SCHEMA",
      );
    }
    throw error;
  }
}
