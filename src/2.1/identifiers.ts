import { canonicalize } from "json-canonicalize";
import { v4, v5 } from "uuid";
import { Identifier, StixObjectType } from "./types";

export const OASIS_NAMESPACE = "00abedb4-aa42-466c-9c01-fed23315a9b7";

export type Any<T> = T & Record<any, any>;

export const generateRandomId = <T extends StixObjectType>(type: T): Identifier<T> => {
    return `${type}--${v4()}`;
};

export const generateDeterministicId = <T extends StixObjectType>(
    type: T,
    props: any,
    namespace: string = OASIS_NAMESPACE,
): Identifier<T> => {
    return `${type}--${v5(canonicalize(props), namespace)}`;
};

export const generateDomainObservableId = (props: Any<{ value: string }>): Identifier<"domain-name"> => {
    return generateDeterministicId("domain-name", { value: props.value });
};

export const generateBundleId = (): Identifier<"bundle"> => {
    return generateRandomId("bundle");
};
