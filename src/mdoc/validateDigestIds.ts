import { MdocValidationError } from "./MdocValidationError";
import { IssuerSignedItem } from "./types/issuerSigned";
import { NameSpace } from "./types/namespaces";

export function validateDigestIds(
  namespaces: Record<NameSpace, IssuerSignedItem[]>,
) {
  for (const namespace of Object.keys(namespaces)) {
    const digestIds = namespaces[namespace]?.map((item) => item.digestID);

    if (!digestIds) continue;

    if (!checkUnique(digestIds)) {
      throw new MdocValidationError(
        `Digest IDs are not unique for namespace ${namespace}`,
        "INVALID_DIGEST_IDS",
      );
    }
  }
}

function checkUnique(digestIds: number[]): boolean {
  return new Set(digestIds).size === digestIds.length;
}
