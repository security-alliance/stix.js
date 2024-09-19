//#region 1 - Overview
export type StixObject = StixCoreObject | StixMetaObject;

export type StixCoreObject = StixDomainObject | StixCyberObservableObject | StixRelationshipObject;

export type StixMetaObject = ExtensionDefinition | LanguageContent | MarkingDefinition;
//#endregion

//#region 2 - Common Data Types
export type Binary = string; // base64 encoded

export type ExternalReference = {
    source_name: string;
    description?: string;
    url?: string;
    hashes?: Hashes;
    external_id?: string;
};

export type Float = number;

export type Hashes = Record<HashAlgorithmOv, string>;

export type Hex = string;

export type Identifier = `${string}--${string}`;

export type Integer = number;

export type KillChainPhase = {
    kill_chain_name: string;
    phase_name: string;
    [key: `x_${string}`]: unknown;
};

export type Timestamp = string;
//#endregion

//#region 3 - STIX General Concepts
export type CommonProperties = {
    type: string;
    spec_version: string;
    id: Identifier;
    created_by_ref: Identifier;
    created: Timestamp;
    modified: Timestamp;
    revoked: boolean;
    labels: string[];
    confidence: Integer;
    lang: string;
    external_references: ExternalReference[];
    object_marking_refs: Identifier[];
    granular_markings: any[]; //TODO: type this properly
    defanged: boolean;
    extensions: Record<string, any>; //TODO: type this properly
};

type NeverProperties<T> = {
    [P in keyof T]?: never;
};

export type BaseStixObject<
    RequiredKeys extends keyof CommonProperties,
    OptionalKeys extends keyof CommonProperties,
    NotApplicableKeys extends keyof CommonProperties,
    Type extends string,
> = Pick<CommonProperties, RequiredKeys> &
    Partial<Pick<CommonProperties, OptionalKeys>> &
    NeverProperties<Pick<CommonProperties, NotApplicableKeys>> & {
        type: Type;
        id: `${Type}--${string}`;
        [key: `x_${string}`]: unknown;
    };

export type CommonRelationshipType = "derived-from" | "duplicate-of" | "related-to";
//#endregion

//#region 4 - STIX Domain Objects
export type StixDomainObject =
    | AttackPattern
    | Campaign
    | CourseOfAction
    | Grouping
    | Identity
    | Incident
    | Indicator
    | Infrastructure
    | IntrusionSet
    | Location
    | Malware
    | MalwareAnalysis
    | Note
    | ObservedData
    | Opinion
    | Report
    | ThreatActor
    | Tool
    | Vulnerability;
export type AttackPattern = BaseStixObject<
    "type" | "spec_version" | "id" | "created" | "modified",
    | "created_by_ref"
    | "revoked"
    | "labels"
    | "confidence"
    | "lang"
    | "external_references"
    | "object_marking_refs"
    | "granular_markings"
    | "extensions",
    "defanged",
    "attack-pattern"
> & {
    name: string;
    description?: string;
    aliases?: string[];
    kill_chain_phases?: KillChainPhase[];
};

export type AttackPatternRelationshipType = "delivers" | "targets" | "uses";

export type Campaign = any;

export type CourseOfAction = any;

export type Grouping = any;

export type Identity = BaseStixObject<
    "type" | "spec_version" | "id" | "created" | "modified",
    | "created_by_ref"
    | "revoked"
    | "labels"
    | "confidence"
    | "lang"
    | "external_references"
    | "object_marking_refs"
    | "granular_markings"
    | "extensions",
    "defanged",
    "identity"
> & {
    name: string;
    description?: string;
    roles?: string[];
    identity_class?: IdentityClassOv;
    sectors?: IndustrySectorOv[];
    contact_information?: string;
};

export type Incident = BaseStixObject<
    "type" | "spec_version" | "id" | "created" | "modified",
    | "created_by_ref"
    | "revoked"
    | "labels"
    | "confidence"
    | "lang"
    | "external_references"
    | "object_marking_refs"
    | "granular_markings"
    | "extensions",
    "defanged",
    "incident"
> & {
    name: string;
    description?: string;
};

export type Indicator = BaseStixObject<
    "type" | "spec_version" | "id" | "created" | "modified",
    | "created_by_ref"
    | "revoked"
    | "labels"
    | "confidence"
    | "lang"
    | "external_references"
    | "object_marking_refs"
    | "granular_markings"
    | "extensions",
    "defanged",
    "indicator"
> & {
    name?: string;
    description?: string;
    indicator_types?: IndicatorTypeOv[];
    pattern: string;
    pattern_type: PatternTypeOv[];
    pattern_version?: string;
    valid_from: Timestamp;
    valid_until?: Timestamp;
    kill_chain_phases?: KillChainPhase[];
};

export type Infrastructure = any;

export type IntrusionSet = any;

export type Location = any;

export type Malware = any;

export type MalwareAnalysis = any;

export type Note = any;

export type ObservedData = any;

export type Opinion = any;

export type Report = any;

export type ThreatActor = any;

export type Tool = any;

export type Vulnerability = any;
//#endregion

//#region 5 - STIX Relationship Objects
export type StixRelationshipObject = Relationship | Sighting;

export type Relationship = any;

export type Sighting = any;
//#endregion

//#region 6 - STIX Cyber-observable Objects
export type StixCyberObservableObject =
    | Artifact
    | AutonomousSystem
    | Directory
    | DomainName
    | EmailAddress
    | EmailMessage
    | File
    | IPv4Address
    | IPv6Address
    | MACAddress
    | Mutex
    | NetworkTraffic
    | Process
    | Software
    | URL
    | UserAccount
    | WindowsRegistryKey
    | X509Certificate;

export type Artifact = any;
export type AutonomousSystem = any;
export type Directory = any;
export type DomainName = BaseStixObject<
    "type" | "id",
    "spec_version" | "object_marking_refs" | "granular_markings" | "defanged" | "extensions",
    "created_by_ref" | "revoked" | "labels" | "confidence" | "lang" | "external_references",
    "domain-name"
> & {
    value: string;
    resolves_to_refs?: Identifier[];
};
export type EmailAddress = any;
export type EmailMessage = any;
export type File = any;
export type IPv4Address = any;
export type IPv6Address = any;
export type MACAddress = any;
export type Mutex = any;
export type NetworkTraffic = any;
export type Process = any;
export type Software = any;
export type URL = BaseStixObject<
    "type" | "id",
    "spec_version" | "object_marking_refs" | "granular_markings" | "defanged" | "extensions",
    "created_by_ref" | "revoked" | "labels" | "confidence" | "lang" | "external_references",
    "url"
> & {
    value: string;
};
export type UserAccount = any;
export type WindowsRegistryKey = any;
export type X509Certificate = any;

//#endregion

//#region 7 - STIX Meta Objects
export type LanguageContent = any;

export type MarkingDefinition = any;

export type GranularMarking = any;

export type ExtensionDefinition = any;
//#endregion

//#region 8 - STIX Bundle Object
export type Bundle = {
    type: "bundle";
    id: `bundle--${string}`;
    objects: StixObject[];
};
//#endregion

//#region 10 - STIX Vocabularies
export type OpenVocabulary<Literal> = Literal | (string & Record<never, never>);

export type HashAlgorithmOv = OpenVocabulary<
    "MD5" | "SHA-1" | "SHA-256" | "SHA-512" | "SHA3-256" | "SHA3-512" | "SSDEEP" | "TLSH"
>;

export type IdentityClassOv = OpenVocabulary<"individual" | "group" | "system" | "organization" | "class" | "unknown">;

export type IndustrySectorOv = OpenVocabulary<"">;

export type IndicatorTypeOv = OpenVocabulary<"">;

export type PatternTypeOv = OpenVocabulary<"">;
//#endregion
