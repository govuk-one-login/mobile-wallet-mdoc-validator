import { Tag } from "cbor2";
import { TAGS } from "./constants/tags";
import { TaggedIssuerSigned } from "./schemas/issuerSignedSchema";
import { errorMessage, MdocValidationError } from "./MdocValidationError";

export function validateTags(taggedIssuerSigned: TaggedIssuerSigned): void {
  try {
    for (const [namespaceName, elements] of Object.entries(
      taggedIssuerSigned.nameSpaces,
    )) {
      for (const element of elements) {
        validateNamespacesTags(element, namespaceName);
      }
    }
  } catch (error) {
    throw new MdocValidationError(
      `Failed to validate tags - ${errorMessage(error)}`,
      "INVALID_TAGS",
    );
  }
}

function validateNamespacesTags(element: Tag, namespaceName: string): void {
  if (element.tag !== TAGS.ENCODED_CBOR_DATA) {
    throw new Error(
      `IssuerSignedItem in namespace '${namespaceName}' missing tag '${TAGS.ENCODED_CBOR_DATA.toString()}'`,
    );
  }
}
