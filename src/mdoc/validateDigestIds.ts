import { MDLValidationError } from "./MDLValidationError";
import { IssuerSignedItem } from "./types/issuerSigned";
import { NameSpace } from "./types/namespaces";

export function validateDigestIds(
  namespaces: Record<NameSpace, IssuerSignedItem[]>,
) {
  for (const namespace of Object.keys(namespaces)) {
    const digestIds = namespaces[namespace]?.map((item) => item.digestID);

    if (!checkUnique(digestIds)) {
      throw new MDLValidationError(
        `Digest IDs are not unique for namespace ${namespace}`,
        "INVALID_DIGEST_IDS",
      );
    }
  }
}

function checkUnique(digestIds: number[]): boolean {
  return new Set(digestIds).size === digestIds.length;
}
