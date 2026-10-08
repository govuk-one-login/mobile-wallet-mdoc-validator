import { z } from "zod";

/**
 * Returns true if every code point in the string is within the Latin-1
 * (ISO/IEC 8859-1) range, i.e. U+0000–U+00FF.
 */
export function isLatin1(value: string): boolean {
  for (const char of value) {
    const codePoint = char.codePointAt(0);
    if (codePoint === undefined || codePoint > 0x00ff) {
      return false;
    }
  }
  return true;
}

/**
 * A reusable Zod string refinement that enforces Latin-1 (ISO/IEC 8859-1)
 * characters only.
 */
export const latin1String = z.string().refine(isLatin1, {
  message: "must contain only Latin1 (ISO/IEC 8859-1) characters",
});

/**
 * A Latin-1 (ISO/IEC 8859-1) string that is non-empty and at most 128
 * characters. Empty strings are rejected.
 */
export const latin1StringMax128 = z.string().min(1).max(128).refine(isLatin1, {
  message: "must contain only Latin1 (ISO/IEC 8859-1) characters",
});

/**
 * A Latin-1 (ISO/IEC 8859-1) string that is non-empty and at most 256
 * characters. Empty strings are rejected.
 */
export const latin1StringMax256 = z.string().min(1).max(256).refine(isLatin1, {
  message: "must contain only Latin1 (ISO/IEC 8859-1) characters",
});
