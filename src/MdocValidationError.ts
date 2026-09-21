export class MdocValidationError extends Error {
  public readonly code: string;

  constructor(message: string, code = "VALIDATION_FAILED") {
    super(message);
    this.name = "MdocValidationError";
    this.code = code;
  }
}

export function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
