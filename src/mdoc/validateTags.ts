import { decode, Tag } from "cbor2";
import { TAGS } from "./constants/tags";
import { TaggedIssuerSigned } from "./types/issuerSigned";
import { errorMessage, MDLValidationError } from "./MDLValidationError";
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
    throw new MDLValidationError(
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

  // TODO: Should we replace this with something else? E.g., if element value is in acceptable date format, check tag
  // const decodedItem: TaggedIssuerSignedItem = decode(
  //   element.contents as Uint8Array,
  // );
  //
  // if (FULL_DATE_ELEMENTS.has(decodedItem.elementIdentifier)) {
  //   if (
  //     !(decodedItem.elementValue instanceof Tag) ||
  //     decodedItem.elementValue.tag !== TAGS.FULL_DATE
  //   ) {
  //     throw new Error(
  //       `'${decodedItem.elementIdentifier}' missing tag '${TAGS.FULL_DATE}'`,
  //     );
  //   }
  // }
}

function validateMobileSecurityObjectTags(payload: Uint8Array) {
  const taggedMsoBytes: Tag = decode(payload);
  if (taggedMsoBytes.tag !== TAGS.ENCODED_CBOR_DATA) {
    throw new Error(
      `MobileSecurityObjectBytes missing tag '${TAGS.ENCODED_CBOR_DATA.toString()}'`,
    );
  }
  const mso = decode(
    taggedMsoBytes.contents as Uint8Array,
  ) as TaggedMobileSecurityObject;

  const taggedValidityInfo = mso.validityInfo;

  if (
    taggedValidityInfo.signed &&
    taggedValidityInfo.signed.tag !== TAGS.DATE_TIME
  ) {
    throw new Error(
      `'signed' in 'ValidityInfo' missing tag ${TAGS.DATE_TIME.toString()}`,
    );
  }

  if (
    taggedValidityInfo.validFrom &&
    taggedValidityInfo.validFrom.tag !== TAGS.DATE_TIME
  ) {
    throw new Error(
      `'validFrom' in 'ValidityInfo' missing tag ${TAGS.DATE_TIME.toString()}`,
    );
  }

  if (
    taggedValidityInfo.validUntil &&
    taggedValidityInfo.validUntil.tag !== TAGS.DATE_TIME
  ) {
    throw new Error(
      `'validUntil' in 'ValidityInfo' missing tag ${TAGS.DATE_TIME.toString()}`,
    );
  }
}
