// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Signature checks used by C2PA: RSA PKCS#1 v1.5 and RSA-PSS (both SHA-256, e = 65537) through
/// the modexp precompile, and ECDSA P-256 through the P256VERIFY precompile at 0x100, which
/// Monad provides natively.
library Sig {
    address constant MODEXP = address(0x05);
    address constant P256VERIFY = address(0x100);
    bytes constant DIGEST_INFO_SHA256 = hex"3031300d060960864801650304020105000420";

    function rsaRaw(bytes memory s, bytes memory n) internal view returns (bytes memory) {
        require(s.length == n.length, "rsa: sig length");
        (bool ok, bytes memory out) =
            MODEXP.staticcall(abi.encodePacked(s.length, uint256(3), n.length, s, hex"010001", n));
        require(ok && out.length == n.length, "rsa: modexp");
        return out;
    }

    function pkcs1Sha256(bytes32 h, bytes memory s, bytes memory n) internal view returns (bool) {
        bytes memory em = rsaRaw(s, n);
        uint256 k = n.length;
        uint256 ps = k - 3 - DIGEST_INFO_SHA256.length - 32;
        bytes memory pad = new bytes(ps);
        for (uint256 i; i < ps; i++) pad[i] = 0xff;
        return keccak256(em) == keccak256(abi.encodePacked(hex"0001", pad, hex"00", DIGEST_INFO_SHA256, h));
    }

    /// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt, as COSE PS256 requires.
    function pssSha256(bytes32 h, bytes memory s, bytes memory n) internal view returns (bool) {
        bytes memory em = rsaRaw(s, n);
        uint256 modBits = bitLen(n);
        uint256 emBits = modBits - 1;
        uint256 emLen = (emBits + 7) / 8;
        uint256 off = em.length - emLen; // 1 when modBits is a multiple of 8
        if (off == 1 && em[0] != 0) return false;
        if (uint8(em[em.length - 1]) != 0xbc) return false;
        uint256 dbLen = emLen - 33;
        bytes32 hh;
        assembly {
            hh := mload(add(add(em, 32), add(off, dbLen)))
        }
        bytes memory db = new bytes(dbLen);
        for (uint256 c; c * 32 < dbLen; c++) {
            bytes32 m = sha256(abi.encodePacked(hh, uint32(c)));
            for (uint256 i; i < 32 && c * 32 + i < dbLen; i++) {
                db[c * 32 + i] = em[off + c * 32 + i] ^ m[i];
            }
        }
        db[0] = db[0] & bytes1(uint8(0xff >> (8 * emLen - emBits)));
        uint256 ps = dbLen - 32 - 1;
        for (uint256 i; i < ps; i++) if (db[i] != 0) return false;
        if (db[ps] != 0x01) return false;
        bytes32 salt;
        assembly {
            salt := mload(add(add(db, 32), add(ps, 1)))
        }
        return sha256(abi.encodePacked(bytes8(0), h, salt)) == hh;
    }

    function p256(bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) internal view returns (bool) {
        (bool ok, bytes memory out) = P256VERIFY.staticcall(abi.encode(h, r, s, x, y));
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }

    function bitLen(bytes memory n) private pure returns (uint256) {
        uint256 i;
        while (i < n.length && n[i] == 0) i++;
        uint8 top = uint8(n[i]);
        uint256 bits;
        while (top > 0) (top, bits) = (top >> 1, bits + 1);
        return (n.length - i - 1) * 8 + bits;
    }
}
