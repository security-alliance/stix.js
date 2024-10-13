import { canonicalize } from "json-canonicalize";
import { v4, v5 } from "uuid";
import { Identifier, OpenVocabulary, StixObjectType } from "./types.js";

export const OASIS_NAMESPACE = "00abedb4-aa42-466c-9c01-fed23315a9b7";

export type Any<T> = T & Record<any, any>;

export const isIdentifierType = <T extends string>(id: Identifier<any>, type: T): id is Identifier<T> => {
    return id.startsWith(`${type}--`);
};

export const generateRandomId = <T extends OpenVocabulary<StixObjectType>>(type: T): Identifier<T> => {
    return `${type}--${v4()}`;
};

export const generateDeterministicId = <T extends OpenVocabulary<StixObjectType>>(
    type: T,
    props: any,
    namespace: string = OASIS_NAMESPACE,
): Identifier<T> => {
    return `${type}--${v5(canonicalize(props), namespace)}`;
};

export const toValueObject = (valueOrProps: string | Any<{ value: string }>): object => {
    return toSinglePropertyObject("value", valueOrProps);
};

export const toSinglePropertyObject = <T extends string>(
    key: T,
    valueOrProps: string | Any<{ [T: string]: string }>,
): object => {
    return { [key]: typeof valueOrProps === "object" ? valueOrProps.value : valueOrProps };
};

export const generateDomainNameId = (valueOrProps: string | Any<{ value: string }>): Identifier<"domain-name"> => {
    return generateDeterministicId("domain-name", toValueObject(valueOrProps));
};

export const generateUrlId = (valueOrProps: string | Any<{ value: string }>): Identifier<"url"> => {
    return generateDeterministicId("url", toValueObject(valueOrProps));
};

export const generateIPv4AddrId = (valueOrProps: string | Any<{ value: string }>): Identifier<"ipv4-addr"> => {
    return generateDeterministicId("ipv4-addr", toValueObject(valueOrProps));
};

export const generateIPv6AddrId = (valueOrProps: string | Any<{ value: string }>): Identifier<"ipv6-addr"> => {
    return generateDeterministicId("ipv6-addr", toValueObject(valueOrProps));
};

export const generateBundleId = (): Identifier<"bundle"> => {
    return generateRandomId("bundle");
};
