// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Reads what the registry needs from a DER TBSCertificate: the signature algorithm the issuer
/// used, the subject's O and CN, and the subject public key (RSA modulus with e = 65537, or an
/// uncompressed P-256 point). It walks the structure field by field, so a caller cannot point it
/// at the issuer's name or at bytes that only look like a key.
library X509 {
    error BadDER();
    error UnsupportedKey();

    bytes constant OID_RSA = hex"2a864886f70d010101";
    bytes constant OID_EC = hex"2a8648ce3d0201";
    bytes constant OID_P256 = hex"2a8648ce3d030107";
    bytes constant OID_O = hex"55040a";
    bytes constant OID_CN = hex"550403";

    enum KeyType {
        None,
        RSA,
        P256
    }

    struct Cert {
        bytes sigAlg; // OID of the algorithm the issuer signed this TBS with
        string org;
        string cn;
        KeyType keyType;
        bytes rsaModulus;
        bytes32 x;
        bytes32 y;
    }

    function hdr(bytes calldata b, uint256 p) internal pure returns (uint8 tag, uint256 start, uint256 end) {
        tag = uint8(b[p]);
        uint8 l = uint8(b[p + 1]);
        if (l < 0x80) {
            start = p + 2;
            end = start + l;
        } else {
            uint256 nb = l & 0x7f;
            if (nb == 0 || nb > 4) revert BadDER();
            uint256 len;
            for (uint256 i; i < nb; i++) len = (len << 8) | uint8(b[p + 2 + i]);
            start = p + 2 + nb;
            end = start + len;
        }
        if (end > b.length) revert BadDER();
    }

    function expect(bytes calldata b, uint256 p, uint8 want) private pure returns (uint256 start, uint256 end) {
        uint8 tag;
        (tag, start, end) = hdr(b, p);
        if (tag != want) revert BadDER();
    }

    function parse(bytes calldata tbs) internal pure returns (Cert memory c) {
        (uint256 p, uint256 tbsEnd) = expect(tbs, 0, 0x30);
        if (tbsEnd != tbs.length) revert BadDER();
        (uint8 tag,, uint256 e) = hdr(tbs, p);
        if (tag == 0xa0) p = e; // explicit version
        (,, p) = hdr(tbs, p); // serial
        (uint256 as_, uint256 ae) = expect(tbs, p, 0x30); // signature algorithm
        (uint256 os, uint256 oe) = expect(tbs, as_, 0x06);
        c.sigAlg = tbs[os:oe];
        p = ae;
        (,, p) = hdr(tbs, p); // issuer
        (,, p) = hdr(tbs, p); // validity
        (uint256 ss, uint256 se) = expect(tbs, p, 0x30); // subject
        (c.org, c.cn) = names(tbs, ss, se);
        readKey(tbs, se, c);
    }

    function names(bytes calldata b, uint256 p, uint256 end) private pure returns (string memory org, string memory cn) {
        while (p < end) {
            (uint256 rs, uint256 re) = expect(b, p, 0x31); // RDN set
            (uint256 qs,) = expect(b, rs, 0x30); // attribute
            (uint256 os, uint256 oe) = expect(b, qs, 0x06);
            (, uint256 vs, uint256 ve) = hdr(b, oe);
            bytes32 oid = keccak256(b[os:oe]);
            if (oid == keccak256(OID_O)) org = string(b[vs:ve]);
            else if (oid == keccak256(OID_CN)) cn = string(b[vs:ve]);
            p = re;
        }
    }

    function readKey(bytes calldata b, uint256 p, Cert memory c) private pure {
        (uint256 ks,) = expect(b, p, 0x30); // SubjectPublicKeyInfo
        (uint256 as_, uint256 ae) = expect(b, ks, 0x30); // AlgorithmIdentifier
        (uint256 os, uint256 oe) = expect(b, as_, 0x06);
        (uint256 bs, uint256 be) = expect(b, ae, 0x03); // BIT STRING
        if (b[bs] != 0) revert BadDER();
        bytes32 alg = keccak256(b[os:oe]);
        if (alg == keccak256(OID_RSA)) {
            (uint256 rs,) = expect(b, bs + 1, 0x30);
            (uint256 ns, uint256 ne) = expect(b, rs, 0x02);
            (uint256 es, uint256 ee) = expect(b, ne, 0x02);
            if (keccak256(b[es:ee]) != keccak256(hex"010001")) revert UnsupportedKey();
            if (b[ns] == 0) ns++;
            c.keyType = KeyType.RSA;
            c.rsaModulus = b[ns:ne];
        } else if (alg == keccak256(OID_EC)) {
            (uint256 cs, uint256 ce) = expect(b, oe, 0x06);
            if (keccak256(b[cs:ce]) != keccak256(OID_P256)) revert UnsupportedKey();
            if (be - bs != 66 || b[bs + 1] != 0x04) revert UnsupportedKey();
            c.keyType = KeyType.P256;
            c.x = bytes32(b[bs + 2:bs + 34]);
            c.y = bytes32(b[bs + 34:bs + 66]);
        } else {
            revert UnsupportedKey();
        }
    }

    /// r and s from a DER ECDSA-Sig-Value.
    function ecdsaSig(bytes calldata sig) internal pure returns (bytes32 r, bytes32 s) {
        (uint256 p,) = expect(sig, 0, 0x30);
        (uint256 rs, uint256 re) = expect(sig, p, 0x02);
        (uint256 ss, uint256 se) = expect(sig, re, 0x02);
        r = toWord(sig[rs:re]);
        s = toWord(sig[ss:se]);
    }

    function toWord(bytes calldata v) private pure returns (bytes32 out) {
        while (v.length > 32 && v[0] == 0) v = v[1:];
        if (v.length > 32) revert BadDER();
        out = bytes32(v) >> (8 * (32 - v.length));
    }
}
