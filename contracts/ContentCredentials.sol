// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CBOR} from "./lib/CBOR.sol";
import {X509} from "./lib/X509.sol";
import {Sig} from "./lib/Sig.sol";
import {ECDSA384} from "./vendor/nitro/vendor/ECDSA384.sol";
import {ECDSA384Curve} from "./vendor/nitro/ECDSA384Curve.sol";
import {Sha2Ext} from "./vendor/nitro/Sha2Ext.sol";

/// Unstripped: a public registry of C2PA Content Credentials whose signatures the chain itself
/// verifies. Anyone can submit the credential an AI model or camera embedded in a file. The
/// contract checks the certificate chain up to a trust anchor, the COSE signature over the
/// claim, and the hard-binding assertion, then records the signed hash of the asset. A copy of
/// the file whose metadata was stripped still hashes to that value, so its origin can be looked
/// up by anyone, without trusting whoever submitted it or whoever runs a manifest cloud.
contract ContentCredentials {
    error UnknownIssuer(bytes32 issuer);
    error BadCertSignature();
    error UnsupportedAlg(int256 alg);
    error BadClaimSignature();
    error MissingAssertion(string name);
    error AssertionMismatch(string name);

    bytes constant OID_SHA256_RSA = hex"2a864886f70d01010b";
    bytes constant OID_ECDSA_SHA256 = hex"2a8648ce3d040302";
    bytes constant OID_ECDSA_SHA384 = hex"2a8648ce3d040303";
    int256 constant ES256 = -7;
    int256 constant PS256 = -37;

    struct Issuer {
        X509.KeyType keyType;
        bytes key; // RSA modulus or EC point x || y
        bytes32 parent; // 0 for a trust anchor
        string org;
        string cn;
    }

    /// Everything here comes out of the file's own C2PA manifest (see sdk/extract.ts).
    struct Credential {
        bytes32 issuer; // id of the CA that issued the signing certificate
        bytes leafTbs; // the signing certificate, to-be-signed part
        bytes leafSig; // the CA's signature over leafTbs
        bytes protectedHeader; // COSE_Sign1 protected header
        bytes claim; // the claim, which is the COSE payload
        bytes signature; // COSE_Sign1 signature
        bytes hashAssertion; // the c2pa.hash.data assertion superbox (jumd + cbor boxes)
        bytes actionsAssertion; // the c2pa.actions(.v2) assertion superbox, or empty
    }

    struct Record {
        bytes32 issuer;
        bytes32 claimHash;
        address registrant;
        uint64 registeredAt;
        uint64 registeredBlock;
        int16 alg;
        bool aiGenerated; // digitalSourceType is trainedAlgorithmicMedia or a composite with it
        string signerOrg; // O of the signing certificate
        string signerName; // CN of the signing certificate
        string generator; // claim_generator_info.name
        string sourceType; // digitalSourceType of the first action that declares one
    }

    mapping(bytes32 => Issuer) public issuers;
    mapping(bytes32 => Record) private records;
    bytes32[] public assets;

    event IssuerAdded(bytes32 indexed id, bytes32 indexed parent, string org, string cn);
    event Registered(
        bytes32 indexed assetHash, bytes32 indexed issuer, address indexed registrant, string signerOrg, bool aiGenerated
    );

    /// Trust anchors come from the C2PA trust list. The deployer adds them once and seals the
    /// list; after `seal` nobody, including the deployer, can add or remove an anchor.
    address public immutable deployer = msg.sender;
    bool public sealed_;

    function addAnchor(bytes calldata tbs) external returns (bytes32) {
        require(msg.sender == deployer && !sealed_, "anchors sealed");
        return _addIssuer(X509.parse(tbs), 0);
    }

    function seal() external {
        require(msg.sender == deployer, "deployer only");
        sealed_ = true;
    }

    /// Anyone can add an intermediate CA or a signing certificate, as long as an existing issuer
    /// signed it. `hints` are the modular inverses for a P-384 parent, computed off chain
    /// (tools/p384_hints.js) and each checked on chain, so a wrong hint can only make this revert.
    function addIssuer(bytes calldata tbs, bytes calldata sig, bytes32 parent, bytes calldata hints)
        external
        returns (bytes32)
    {
        X509.Cert memory c = X509.parse(tbs);
        if (!certSigned(parent, tbs, c.sigAlg, sig, hints)) revert BadCertSignature();
        return _addIssuer(c, parent);
    }

    function register(Credential calldata c) external returns (bytes32 assetHash) {
        X509.Cert memory leaf = X509.parse(c.leafTbs);
        // The signing certificate is either already a known issuer (added through addIssuer, which
        // verified its chain), or the issuer named in the credential signed it.
        bool known = c.issuer == keyId(leaf) && issuers[c.issuer].keyType != X509.KeyType.None;
        if (known) {
            // leafTbs was not verified on this path, only its key matched; take the name from the
            // certificate that addIssuer verified, so the key holder cannot sign under another name.
            leaf.org = issuers[c.issuer].org;
            leaf.cn = issuers[c.issuer].cn;
        } else if (!certSigned(c.issuer, c.leafTbs, leaf.sigAlg, c.leafSig, "")) {
            revert BadCertSignature();
        }

        int256 alg = coseAlg(c.protectedHeader);
        bytes32 h = sha256(
            abi.encodePacked(
                hex"846a5369676e617475726531", // array(4), "Signature1"
                CBOR.bstrHeader(c.protectedHeader.length),
                c.protectedHeader,
                hex"40", // empty external_aad
                CBOR.bstrHeader(c.claim.length),
                c.claim
            )
        );
        if (!claimSigned(alg, h, c.signature, leaf)) revert BadClaimSignature();

        bytes32 hashH = assertionHash(c.claim, "c2pa.hash.data");
        if (hashH == 0) revert MissingAssertion("c2pa.hash.data");
        if (sha256(c.hashAssertion) != hashH) revert AssertionMismatch("c2pa.hash.data");
        assetHash = bytes32(CBOR.bstr(c.hashAssertion, CBOR.find(c.hashAssertion, cborStart(c.hashAssertion), "hash")));

        if (records[assetHash].registeredAt != 0) return assetHash;

        Record storage r = records[assetHash];
        r.issuer = c.issuer;
        r.claimHash = sha256(c.claim);
        r.registrant = msg.sender;
        r.registeredAt = uint64(block.timestamp);
        r.registeredBlock = uint64(block.number);
        r.alg = int16(alg);
        r.signerOrg = leaf.org;
        r.signerName = leaf.cn;
        r.generator = generatorName(c.claim);
        if (c.actionsAssertion.length != 0) readActions(c.claim, c.actionsAssertion, r);
        assets.push(assetHash);
        emit Registered(assetHash, c.issuer, msg.sender, leaf.org, r.aiGenerated);
    }

    /// Issuer id of the key in a TBSCertificate: what `register` expects in `Credential.issuer`.
    function idOf(bytes calldata tbs) external pure returns (bytes32) {
        return keyId(X509.parse(tbs));
    }

    function provenanceOf(bytes32 assetHash) external view returns (Record memory) {
        return records[assetHash];
    }

    function isRegistered(bytes32 assetHash) external view returns (bool) {
        return records[assetHash].registeredAt != 0;
    }

    function isAIGenerated(bytes32 assetHash) external view returns (bool) {
        return records[assetHash].aiGenerated;
    }

    function assetCount() external view returns (uint256) {
        return assets.length;
    }

    // --- checks ---------------------------------------------------------------------------

    function certSigned(bytes32 issuerId, bytes calldata tbs, bytes memory sigAlg, bytes calldata sig, bytes memory hints)
        internal
        view
        returns (bool)
    {
        Issuer storage i = issuers[issuerId];
        if (i.keyType == X509.KeyType.None) revert UnknownIssuer(issuerId);
        if (i.keyType == X509.KeyType.RSA) {
            return keccak256(sigAlg) == keccak256(OID_SHA256_RSA) && Sig.pkcs1Sha256(sha256(tbs), sig, i.key);
        }
        if (i.keyType == X509.KeyType.P256) {
            if (keccak256(sigAlg) != keccak256(OID_ECDSA_SHA256)) return false;
            bytes memory rs = X509.ecdsaSig(sig, 32);
            (bytes32 r, bytes32 s, bytes32 x, bytes32 y) = (word(rs, 0), word(rs, 32), word(i.key, 0), word(i.key, 32));
            return Sig.p256(sha256(tbs), r, s, x, y);
        }
        // P-384, which C2PA CAs such as Google's and Trufo's use. No precompile exists for it, so this
        // runs in Solidity (Solarity's ECDSA384 as vendored by base/nitro-validator); it is only
        // needed once per certificate, when the certificate is added as an issuer.
        if (keccak256(sigAlg) != keccak256(OID_ECDSA_SHA384)) return false;
        bytes memory m = tbs;
        bytes memory h384 = Sha2Ext.sha384(m, 0, m.length);
        bytes memory rs = X509.ecdsaSig(sig, 48);
        if (hints.length == 0) return ECDSA384.verify(ECDSA384Curve.p384(), h384, rs, i.key);
        return ECDSA384.verifyWithHints(ECDSA384Curve.p384(), h384, rs, i.key, hints);
    }

    function claimSigned(int256 alg, bytes32 h, bytes calldata sig, X509.Cert memory leaf)
        internal
        view
        returns (bool)
    {
        if (alg == PS256 && leaf.keyType == X509.KeyType.RSA) return Sig.pssSha256(h, sig, leaf.key);
        if (alg == ES256 && leaf.keyType == X509.KeyType.P256 && sig.length == 64) {
            return Sig.p256(h, bytes32(sig[:32]), bytes32(sig[32:]), word(leaf.key, 0), word(leaf.key, 32));
        }
        revert UnsupportedAlg(alg);
    }

    /// COSE header label 1 (alg) from the protected header map.
    function coseAlg(bytes calldata ph) internal pure returns (int256) {
        (uint8 mt, uint64 n, uint256 q) = CBOR.head(ph, 0);
        require(mt == 5, "cose: header");
        for (uint256 i; i < n; i++) {
            (uint8 kt, uint64 kv,) = CBOR.head(ph, q);
            uint256 vp = CBOR.skip(ph, q);
            if (kt == 0 && kv == 1) {
                (uint8 vt, uint64 v,) = CBOR.head(ph, vp);
                return vt == 1 ? -1 - int256(uint256(v)) : int256(uint256(v));
            }
            q = CBOR.skip(ph, vp);
        }
        revert UnsupportedAlg(0);
    }

    /// The hash the signed claim lists for the assertion whose URL ends in `name`, or 0.
    function assertionHash(bytes calldata claim, bytes memory name) internal pure returns (bytes32) {
        uint256 p = CBOR.find(claim, 0, "created_assertions"); // v2 claims
        if (p == 0) p = CBOR.find(claim, 0, "assertions"); // v1 claims
        if (p == 0) return 0;
        (uint8 mt, uint64 n, uint256 q) = CBOR.head(claim, p);
        require(mt == 4, "claim: assertions");
        for (uint256 i; i < n; i++) {
            bytes calldata url = CBOR.text(claim, CBOR.find(claim, q, "url"));
            if (endsWith(url, name)) return bytes32(CBOR.bstr(claim, CBOR.find(claim, q, "hash")));
            q = CBOR.skip(claim, q);
        }
        return 0;
    }

    function generatorName(bytes calldata claim) internal pure returns (string memory) {
        uint256 p = CBOR.find(claim, 0, "claim_generator_info");
        if (p == 0) {
            p = CBOR.find(claim, 0, "claim_generator");
            return p == 0 ? "" : string(CBOR.text(claim, p));
        }
        (uint8 mt,, uint256 q) = CBOR.head(claim, p);
        if (mt == 4) p = q; // v1: array of maps, take the first
        uint256 np = CBOR.find(claim, p, "name");
        return np == 0 ? "" : string(CBOR.text(claim, np));
    }

    bytes constant TRAINED = "trainedAlgorithmicMedia";
    bytes constant COMPOSITE = "compositeWithTrainedAlgorithmicMedia";

    function readActions(bytes calldata claim, bytes calldata box, Record storage r) internal {
        bytes32 h = assertionHash(claim, "c2pa.actions.v2");
        if (h == 0) h = assertionHash(claim, "c2pa.actions");
        if (h == 0) revert MissingAssertion("c2pa.actions");
        if (sha256(box) != h) revert AssertionMismatch("c2pa.actions");
        uint256 p = CBOR.find(box, cborStart(box), "actions");
        (, uint64 n, uint256 q) = CBOR.head(box, p);
        for (uint256 i; i < n; i++) {
            uint256 sp = CBOR.find(box, q, "digitalSourceType");
            if (sp != 0) {
                bytes calldata t = CBOR.text(box, sp);
                r.sourceType = string(t);
                r.aiGenerated = endsWith(t, TRAINED) || endsWith(t, COMPOSITE);
                return;
            }
            q = CBOR.skip(box, q);
        }
    }

    // --- helpers --------------------------------------------------------------------------

    function _addIssuer(X509.Cert memory c, bytes32 parent) internal returns (bytes32 id) {
        id = keyId(c);
        Issuer storage i = issuers[id];
        if (i.keyType != X509.KeyType.None) return id;
        (i.keyType, i.key, i.parent, i.org, i.cn) = (c.keyType, c.key, parent, c.org, c.cn);
        emit IssuerAdded(id, parent, c.org, c.cn);
    }

    function keyId(X509.Cert memory c) internal pure returns (bytes32) {
        return keccak256(c.key);
    }

    /// Offset of the CBOR payload in an assertion superbox: skip the jumd box and the cbor box header.
    function cborStart(bytes calldata box) internal pure returns (uint256) {
        uint256 jl = uint32(bytes4(box[:4]));
        require(bytes4(box[jl + 4:jl + 8]) == "cbor", "assertion: not cbor");
        return jl + 8;
    }

    function word(bytes memory b, uint256 off) internal pure returns (bytes32 w) {
        assembly {
            w := mload(add(add(b, 32), off))
        }
    }

    function endsWith(bytes calldata s, bytes memory suffix) internal pure returns (bool) {
        return s.length >= suffix.length && keccak256(s[s.length - suffix.length:]) == keccak256(suffix);
    }
}
