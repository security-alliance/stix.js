import assert from "node:assert";
import { describe, it } from "node:test";
import {
    generateDomainNameId,
    generateIPv4AddrId,
    generateIPv6AddrId,
    generateUrlId,
    toValueObject,
} from "../src/2.1/identifiers";

describe("STIX 2.1", () => {
    it("should convert a value to an object properly", () => {
        assert.deepStrictEqual(toValueObject("hello"), { value: "hello" });
        assert.deepStrictEqual(toValueObject({ value: "hello" }), { value: "hello" });
    });

    it("should generate ids properly", () => {
        assert.equal(generateDomainNameId("example.com"), "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7");
        assert.equal(generateDomainNameId("control.example.com"), "domain-name--427e3664-0043-5865-b454-97df26649bde");

        assert.equal(generateIPv4AddrId("198.51.100.8"), "ipv4-addr--6c83081b-13af-5e30-ba30-6f401772a083");
        assert.equal(generateIPv4AddrId("198.51.100.9"), "ipv4-addr--4b8ed646-46df-5a9c-b5a6-b3ae128f35a6");

        assert.equal(
            generateIPv6AddrId("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "ipv6-addr--85a85a8c-ee99-5722-946d-3c3a3270fc6f",
        );
        assert.equal(generateIPv6AddrId("2001:0db8::/96"), "ipv6-addr--084d3b4c-7785-568a-a569-0c61c95754ab");

        assert.equal(
            generateUrlId("https://example.com/research/index.html"),
            "url--47c3cf9a-5027-5bf0-997a-017c7edc7c55",
        );
        assert.equal(generateUrlId("ftp://example.com"), "url--ae8ac58b-8274-5e88-b161-45e9b25c4748");
    });
});
