import { decode, Tag } from "cbor2";
import { TAGS } from "./constants/tags";
import { TaggedIssuerSigned } from "./types/issuerSigned";
import { errorMessage, MdocValidationError } from "./MdocValidationError";
import { TaggedMobileSecurityObject } from "./types/mobileSecurityObject";

export function validateTags(taggedIssuerSigned: TaggedIssuerSigned): void {
  try {
    for (const [namespaceName, elements] of Object.entries(
      taggedIssuerSigned.nameSpaces,
    )) {
      for (const element of elements) {
        validateNamespacesTags(element, namespaceName);
      }
    }

    validateMobileSecurityObjectTags(taggedIssuerSigned.issuerAuth[2]);
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

  // TODO: Validate that date element values have the correct CBOR tags (tag 1004 for full-date,
  // tag 0 for date-time). Since the library is document-agnostic, it cannot rely on a known list
  // of date elements. Options to explore:
  // - Detect date-formatted strings and warn/fail if the CBOR tag is missing
  // - Let consumers pass in a list of date elements for their document type
  // - Return warnings for untagged date-like values without failing validation
  // e.g.:
  // const decodedItem = decode(element.contents as Uint8Array);
  // if (looksLikeDate(decodedItem.elementValue)) {
  //   verify element has FULL_DATE (tag 1004) or DATE_TIME (tag 0)
  // }
}

function validateMobileSecurityObjectTags(payload: Uint8Array) {
  const taggedMsoBytes: Tag = decode(payload);
  if (taggedMsoBytes.tag !== TAGS.ENCODED_CBOR_DATA) {
    throw new Error(
      `MobileSecurityObjectBytes missing tag '${TAGS.ENCODED_CBOR_DATA.toString()}'`,
    );
  }
  const mso = decode<TaggedMobileSecurityObject>(
    taggedMsoBytes.contents as Uint8Array,
  );

  const taggedValidityInfo = mso.validityInfo;

  if (taggedValidityInfo.signed.tag !== TAGS.DATE_TIME) {
    throw new Error(
      `'signed' in 'ValidityInfo' missing tag ${TAGS.DATE_TIME.toString()}`,
    );
  }

  if (taggedValidityInfo.validFrom.tag !== TAGS.DATE_TIME) {
    throw new Error(
      `'validFrom' in 'ValidityInfo' missing tag ${TAGS.DATE_TIME.toString()}`,
    );
  }

  if (taggedValidityInfo.validUntil.tag !== TAGS.DATE_TIME) {
    throw new Error(
      `'validUntil' in 'ValidityInfo' missing tag ${TAGS.DATE_TIME.toString()}`,
    );
  }
}
