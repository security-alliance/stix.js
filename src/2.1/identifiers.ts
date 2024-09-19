import { canonicalize } from "json-canonicalize";
import { v4, v5 } from "uuid";
import { Identifier, StixObjectType } from "./types";

export const OASIS_NAMESPACE = "00abedb4-aa42-466c-9c01-fed23315a9b7";

export type Any<T> = T & Record<any, any>;

export const generateId = <T extends StixObjectType>(type: T, props: any): Identifier<T> => {
    return `${type}--${v5(canonicalize(props), OASIS_NAMESPACE)}`;
};

export const generateDomainObservableId = (props: Any<{ value: string }>): Identifier<"domain-name"> => {
    return generateId("domain-name", { value: props.value });
};

export const generateBundleId = (): Identifier<"bundle"> => {
    return `bundle--${v4()}`;
};
