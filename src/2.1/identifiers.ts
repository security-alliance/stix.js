import { canonicalize } from "json-canonicalize";
import { v4, v5 } from "uuid";
import { Identifier } from "./types";

export const OASIS_NAMESPACE = "00abedb4-aa42-466c-9c01-fed23315a9b7";

export type Any<T> = T & Record<any, any>;

export const generateId = (type: string, props: any): Identifier => {
    return `${type}--${v5(canonicalize(props), OASIS_NAMESPACE)}`;
};

export const generateDomainObservableId = (props: Any<{ value: string }>): Identifier => {
    return generateId("domain-name", { value: props.value });
};

export const generateBundleId = (): Identifier => {
    return `bundle--${v4()}`;
};
