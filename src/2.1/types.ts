//#region helpers
export type UUID = string;

export type NeverProperties<T> = {
    [P in keyof T]?: never;
};

export type LiteralUnion<Literal, Base> = Literal | (Base & Record<never, never>);

export type OpenVocabulary<Literal> = LiteralUnion<Literal, string>;
//#endregion

//#region typemaps
/**
 * Users can register custom SDOs, SCOs, and SROs through interface merging
 *
 * There is no support for declaring custom meta objects at this time
 * */
type BuiltinStixDomainObjectTypeMap = { [K in StixDomainObject as K["type"]]: K };

export interface StixDomainObjectTypeMap extends BuiltinStixDomainObjectTypeMap {}

type BuiltinStixCyberObservableObjectTypeMap = { [K in StixCyberObservableObject as K["type"]]: K };

export interface StixCyberObservableObjectTypeMap extends BuiltinStixCyberObservableObjectTypeMap {}

type BuiltinStixRelationshipObjectTypeMap = { [K in StixRelationshipObject as K["type"]]: K };

export interface StixRelationshipObjectTypeMap extends BuiltinStixRelationshipObjectTypeMap {}

export type StixCoreObjectTypeMap = StixDomainObjectTypeMap &
    StixCyberObservableObjectTypeMap &
    StixRelationshipObjectTypeMap;

export type StixMetaObjectTypeMap = { [K in StixMetaObject as K["type"]]: K };

export type StixBundleTypeMap = { bundle: StixBundle };

export type StixObjectTypeMap = StixCoreObjectTypeMap & StixMetaObjectTypeMap & StixBundleTypeMap;
//#endregion

//#region 1 - Overview
export type StixObject = StixCoreObject | StixMetaObject | StixBundle;

export type StixCoreObject = StixDomainObject | StixCyberObservableObject | StixRelationshipObject;

export type StixMetaObject = ExtensionDefinition | LanguageContent | MarkingDefinition;

export type StixObjectType = StixCoreObjectType | StixMetaObjectType | StixBundleType;

export type StixCoreObjectType = StixDomainObjectType | StixCyberObservableObjectType | StixRelationshipObjectType;

export type StixMetaObjectType = StixMetaObject["type"];

export type StixBundleType = StixBundle["type"];

export type StixDomainObjectType = keyof StixDomainObjectTypeMap;

export type StixCyberObservableObjectType = keyof StixCyberObservableObjectTypeMap;

export type StixRelationshipObjectType = keyof StixRelationshipObjectTypeMap;
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

export type Identifier<T extends StixObjectType = StixObjectType> = `${T}--${UUID}`;

export type Integer = number;

export type KillChainPhase = {
    kill_chain_name: string;
    phase_name: string;
} & CustomProperties;

export type Timestamp = string;
//#endregion

//#region 3 - STIX General Concepts
export type CommonProperties<T extends StixObjectType = string> = {
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

export type BaseStixObject<
    Type extends StixObjectType,
    RequiredKeys extends keyof CommonProperties<Type>,
    OptionalKeys extends keyof CommonProperties<Type>,
    NotApplicableKeys extends keyof CommonProperties<Type>,
> = Pick<CommonProperties<Type>, RequiredKeys> &
    Partial<Pick<CommonProperties<Type>, OptionalKeys>> &
    NeverProperties<Pick<CommonProperties<Type>, NotApplicableKeys>> &
    CustomProperties;
//#endregion

//#region 4 - STIX Domain Objects
export type BaseSDORequiredProperties = "type" | "spec_version" | "id" | "created" | "modified";
export type BaseSDOOptionalProperties =
    | "created_by_ref"
    | "revoked"
    | "labels"
    | "confidence"
    | "lang"
    | "external_references"
    | "object_marking_refs"
    | "granular_markings"
    | "extensions";
export type BaseSDONotApplicableProperties = "defanged";

export type BaseStixDomainObject<
    T extends StixObjectType,
    R extends keyof CommonProperties<T> = BaseSDORequiredProperties,
    O extends keyof CommonProperties<T> = BaseSDOOptionalProperties,
    NA extends keyof CommonProperties<T> = BaseSDONotApplicableProperties,
> = BaseStixObject<T, R, O, NA>;

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
    | Vulnerability
    | BaseStixDomainObject<string & Record<never, never>>;

export type AttackPattern = BaseStixDomainObject<"attack-pattern"> & {
    name: string;
    description?: string;
    aliases?: string[];
    kill_chain_phases?: KillChainPhase[];
};

export type AttackPatternRelationshipType = "delivers" | "targets" | "uses";

export type Campaign = BaseStixDomainObject<"campaign">;

export type CourseOfAction = BaseStixDomainObject<"course-of-action">;

export type Grouping = BaseStixDomainObject<"grouping">;

export type Identity = BaseStixDomainObject<"identity"> & {
    name: string;
    description?: string;
    roles?: string[];
    identity_class?: IdentityClassOv;
    sectors?: IndustrySectorOv[];
    contact_information?: string;
};

export type Incident = BaseStixDomainObject<"incident"> & {
    name: string;
    description?: string;
};

export type Indicator = BaseStixDomainObject<"indicator"> & {
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

export type Infrastructure = BaseStixDomainObject<"infrastructure">;

export type IntrusionSet = BaseStixDomainObject<"intrusion-set">;

export type Location = BaseStixDomainObject<"location">;

export type Malware = BaseStixDomainObject<"malware">;

export type MalwareAnalysis = BaseStixDomainObject<"malware-analysis">;

export type Note = BaseStixDomainObject<"note"> & {
    abstract?: string;
    content: string;
    authors?: string[];
    object_refs: Identifier[];
};

export type ObservedData = BaseStixDomainObject<"observed-data">;

export type Opinion = BaseStixDomainObject<"opinion">;

export type Report = BaseStixDomainObject<"report">;

export type ThreatActor = BaseStixDomainObject<"threat-actor">;

export type Tool = BaseStixDomainObject<"tool">;

export type Vulnerability = BaseStixDomainObject<"vulnerability">;
//#endregion

//#region 5 - STIX Relationship Objects
export type StixRelationshipObject = Relationship | Sighting;

export type Relationship = BaseStixDomainObject<"relationship">; //TODO - type these

export type Sighting = BaseStixDomainObject<"sighting">; //TODO - type these
//#endregion

//#region 6 - STIX Cyber-observable Objects
export type BaseSCORequiredProperties = "type" | "id";
export type BaseSCOOptionalProperties =
    | "spec_version"
    | "object_marking_refs"
    | "granular_markings"
    | "defanged"
    | "extensions";
export type BaseSCONotApplicableProperties =
    | "created_by_ref"
    | "revoked"
    | "labels"
    | "confidence"
    | "lang"
    | "external_references";

export type BaseStixCyberObservableObject<
    T extends StixObjectType,
    R extends keyof CommonProperties<T> = BaseSCORequiredProperties,
    O extends keyof CommonProperties<T> = BaseSCOOptionalProperties,
    NA extends keyof CommonProperties<T> = BaseSCONotApplicableProperties,
> = BaseStixObject<T, R, O, NA>;

export type StixCyberObservableObject =
    | Artifact
    | AutonomousSystem
    | Directory
    | DomainName
    | EmailAddress
    | EmailMessage
    | File
    | IPv4Addr
    | IPv6Addr
    | MACAddr
    | Mutex
    | NetworkTraffic
    | Process
    | Software
    | Url
    | UserAccount
    | WindowsRegistryKey
    | X509Certificate
    | BaseStixCyberObservableObject<string & Record<never, never>>;

export type Artifact = BaseStixCyberObservableObject<"artifact">;
export type AutonomousSystem = BaseStixCyberObservableObject<"autonomous-system">;
export type Directory = BaseStixCyberObservableObject<"directory">;
export type DomainName = BaseStixCyberObservableObject<"domain-name"> & {
    value: string;
    resolves_to_refs?: Identifier[];
};
export type EmailAddress = BaseStixCyberObservableObject<"email-address">;
export type EmailMessage = BaseStixCyberObservableObject<"email-message">;
export type File = BaseStixCyberObservableObject<"file">;
export type IPv4Addr = BaseStixCyberObservableObject<"ipv4-addr">;
export type IPv6Addr = BaseStixCyberObservableObject<"ipv6-addr">;
export type MACAddr = BaseStixCyberObservableObject<"mac-addr">;
export type Mutex = BaseStixCyberObservableObject<"mutex">;
export type NetworkTraffic = BaseStixCyberObservableObject<"network-traffic">;
export type Process = BaseStixCyberObservableObject<"process">;
export type Software = BaseStixCyberObservableObject<"software">;
export type Url = BaseStixCyberObservableObject<"url"> & {
    value: string;
};
export type UserAccount = BaseStixCyberObservableObject<"user-account">;
export type WindowsRegistryKey = BaseStixCyberObservableObject<"windows-registry-key">;
export type X509Certificate = BaseStixCyberObservableObject<"x509-certificate">;

//#endregion

//#region 7 - STIX Meta Objects
export type LanguageContent = BaseStixObject<
    "language-content",
    "type" | "spec_version" | "id" | "created" | "modified" | "created_by_ref",
    "revoked" | "labels" | "external_references" | "object_marking_refs" | "granular_markings",
    "confidence" | "lang" | "defanged" | "extensions"
>;

export type MarkingDefinition = ExtensionMarkingDefinition | StatementMarkingDefinition | TLPMarkingDefinition;

export type ExtensionMarkingDefinition = BaseStixObject<
    "marking-definition",
    "type" | "spec_version" | "id" | "created" | "extensions",
    "created_by_ref" | "external_references" | "object_marking_refs" | "granular_markings",
    "modified" | "revoked" | "labels" | "confidence" | "lang" | "defanged"
> & {
    name?: string;
    definition_type?: never;
};

export type StatementMarkingDefinition = BaseStixObject<
    "marking-definition",
    "type" | "spec_version" | "id" | "created",
    "created_by_ref" | "external_references" | "object_marking_refs" | "granular_markings",
    "modified" | "revoked" | "labels" | "confidence" | "lang" | "defanged" | "extensions"
> & {
    name?: string;
    definition_type: "statement";
    definition: {
        statement: string;
    };
};

export type TLPMarkingDefinition = BaseStixObject<
    "marking-definition",
    "type" | "spec_version" | "id" | "created",
    "created_by_ref" | "external_references" | "object_marking_refs" | "granular_markings",
    "modified" | "revoked" | "labels" | "confidence" | "lang" | "defanged" | "extensions"
> & {
    name?: string;
    definition_type: "tlp";
    definition: {
        tlp: OpenVocabulary<"white" | "green" | "amber" | "red">;
    };
};

export type GranularMarking = BaseStixObject<
    "granular-marking",
    "type" | "spec_version" | "id" | "created" | "modified" | "created_by_ref",
    "revoked" | "labels" | "external_references" | "object_marking_refs" | "granular_markings",
    "confidence" | "lang" | "defanged" | "extensions"
>;

export type ExtensionDefinition = BaseStixObject<
    "extension-definition",
    "type" | "spec_version" | "id" | "created" | "modified" | "created_by_ref",
    "revoked" | "labels" | "external_references" | "object_marking_refs" | "granular_markings",
    "confidence" | "lang" | "defanged" | "extensions"
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
export type StixBundleObject<T extends StixObjectType = StixObjectType> = Partial<StixObject> & {
    type: T;
    id: Identifier<T>;
};

export type StixBundle = {
    type: "bundle";
    id: Identifier<"bundle">;
    objects: StixBundleObject[];
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
export interface CustomProperties {
    [key: `x_${string}`]: unknown;
}
//#endregion
