export type UUID = string;

export type NeverProperties<T> = {
    [P in keyof T]?: never;
};

export type LiteralUnion<Literal, Base> = Literal | (Base & Record<never, never>);

export type OpenVocabulary<Literal> = LiteralUnion<Literal, string>;

export type BaseStixObject<
    RequiredKeys extends keyof CommonProperties<Type>,
    OptionalKeys extends keyof CommonProperties<Type>,
    NotApplicableKeys extends keyof CommonProperties<Type>,
    Type extends OpenVocabulary<StixObjectType>,
> = Pick<CommonProperties<Type>, RequiredKeys> &
    Partial<Pick<CommonProperties<Type>, OptionalKeys>> &
    NeverProperties<Pick<CommonProperties<Type>, NotApplicableKeys>> &
    CustomProperties;

//#region 1 - Overview
export type StixObject = StixCoreObject | StixMetaObject;

export type StixObjectType = StixCoreObjectType | StixMetaObjectType | StixBundleType;

export type StixCoreObject = StixDomainObject | StixCyberObservableObject | StixRelationshipObject;

export type StixDomainObjectType =
    | "attack-pattern"
    | "campaign"
    | "course-of-action"
    | "grouping"
    | "identity"
    | "incident"
    | "indicator"
    | "infrastructure"
    | "intrusion-set"
    | "location"
    | "malware"
    | "note"
    | "observed-data"
    | "opinion"
    | "report"
    | "threat-actor"
    | "tool"
    | "vulnerability";

export type StixCyberObservableObjectType =
    | "artifact"
    | "autonomous-system"
    | "directory"
    | "domain-name"
    | "email-address"
    | "email-message"
    | "file"
    | "ipv4-address"
    | "ipv6-address"
    | "mac-address"
    | "mutex"
    | "network-traffic"
    | "process"
    | "software"
    | "url"
    | "user-account"
    | "windows-registry-key"
    | "x509-certificate";

export type StixRelationshipObjectType = "relationship" | "sighting";

export type StixCoreObjectType = StixDomainObjectType | StixCyberObservableObjectType | StixRelationshipObjectType;

export type StixMetaObject = ExtensionDefinition | LanguageContent | MarkingDefinition;

export type StixMetaObjectType = "language-content" | "marking-definition" | "extension-definition";

export type StixBundleType = "bundle";

//#endregion

//#region 2 - Common Data Types
export type Binary = string; // base64 encoded

export type ExternalReference = {
    source_name: string;
    description?: string;
    url?: string;
    hashes?: Hashes;
    external_id?: string;
} & CustomProperties;

export type Float = number;

export type Hashes = Record<HashAlgorithmOv, string>;

export type Hex = string;

export type Identifier<T extends OpenVocabulary<StixObjectType> = string> = `${T}--${UUID}`;

export type Integer = number;

export type KillChainPhase = {
    kill_chain_name: string;
    phase_name: string;
} & CustomProperties;

export type Timestamp = string;
//#endregion

//#region 3 - STIX General Concepts
export type CommonProperties<T extends OpenVocabulary<StixObjectType> = string> = {
    type: T;
    spec_version: string;
    id: Identifier<T>;
    created_by_ref: Identifier<"identity">;
    created: Timestamp;
    modified: Timestamp;
    revoked: boolean;
    labels: string[];
    confidence: Integer;
    lang: string;
    external_references: ExternalReference[];
    object_marking_refs: Identifier<"marking-definition">[];
    granular_markings: GranularMarking[];
    defanged: boolean;
    extensions: Record<string, ExtensionDefinition>;
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

export type MarkingDefinition = ExtensionMarkingDefinition | StatementMarkingDefinition | TLPMarkingDefinition;

export type ExtensionMarkingDefinition = BaseStixObject<
    "type" | "spec_version" | "id" | "created" | "extensions",
    "created_by_ref" | "external_references" | "object_marking_refs" | "granular_markings",
    "modified" | "revoked" | "labels" | "confidence" | "lang" | "defanged",
    "marking-definition"
> & {
    name?: string;
    definition_type?: never;
};

export type StatementMarkingDefinition = BaseStixObject<
    "type" | "spec_version" | "id" | "created",
    "created_by_ref" | "external_references" | "object_marking_refs" | "granular_markings",
    "modified" | "revoked" | "labels" | "confidence" | "lang" | "defanged" | "extensions",
    "marking-definition"
> & {
    name?: string;
    definition_type: "statement";
    definition: {
        statement: string;
    };
};

export type TLPMarkingDefinition = BaseStixObject<
    "type" | "spec_version" | "id" | "created",
    "created_by_ref" | "external_references" | "object_marking_refs" | "granular_markings",
    "modified" | "revoked" | "labels" | "confidence" | "lang" | "defanged" | "extensions",
    "marking-definition"
> & {
    name?: string;
    definition_type: "tlp";
    definition: {
        tlp: OpenVocabulary<"white" | "green" | "amber" | "red">;
    };
};

export type GranularMarking = any;

export type ExtensionDefinition = BaseStixObject<
    "type" | "spec_version" | "id" | "created" | "modified" | "created_by_ref",
    "revoked" | "labels" | "external_references" | "object_marking_refs" | "granular_markings",
    "confidence" | "lang" | "defanged" | "extensions",
    "extension-definition"
> & {
    name: string;
    description?: string;
    schema: string;
    version: string;
    extension_types: "new-sdo" | "new-sco" | "new-sro" | "property-extension" | "toplevel-property-extension";
    extension_properties?: string[];
};
//#endregion

//#region 8 - STIX Bundle Object
export type Bundle = {
    type: "bundle";
    id: Identifier<"bundle">;
    objects: StixObject[];
} & CustomProperties;
//#endregion

//#region 10 - STIX Vocabularies
export type HashAlgorithmOv = OpenVocabulary<
    "MD5" | "SHA-1" | "SHA-256" | "SHA-512" | "SHA3-256" | "SHA3-512" | "SSDEEP" | "TLSH"
>;

export type IdentityClassOv = OpenVocabulary<"individual" | "group" | "system" | "organization" | "class" | "unknown">;

export type IndustrySectorOv = OpenVocabulary<
    | "agriculture"
    | "aerospace"
    | "automotive"
    | "chemical"
    | "commercial"
    | "communications"
    | "construction"
    | "defense"
    | "education"
    | "energy"
    | "entertainment"
    | "financial-services"
    | "government"
    | "emergency-services"
    | "government-local"
    | "government-national"
    | "government-public-services"
    | " government-regional"
    | "healthcare"
    | "hospitality-leisure"
    | "infrastructure"
    | "dams"
    | "nuclear"
    | "water"
    | "insurance"
    | "manufacturing"
    | "mining"
    | "non-profit"
    | "pharmaceuticals"
    | "retail"
    | "technology"
    | "telecommunications"
    | "transportation"
    | "utilities"
>;

export type IndicatorTypeOv = OpenVocabulary<
    "anomalous-activity" | "anonymization" | "benign" | "compromised" | "malicious-activity" | "attribution" | "unknown"
>;

export type PatternTypeOv = OpenVocabulary<"stix" | "pcre" | "sigma" | "snort" | "suricata" | "yara">;
//#endregion

//#region 11 - Customizing STIX
export type CustomProperties = {
    // recommended
    [key: `x_${string}`]: unknown;

    // possible
    [key: string]: unknown;
};
//#endregion
