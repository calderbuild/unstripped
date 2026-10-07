// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal definite-length CBOR reader over calldata. Enough to walk a C2PA claim:
/// maps with text keys, arrays, byte and text strings, ints, tags.
library CBOR {
    error Indefinite();
    error WrongType(uint8 want, uint8 got);

    function head(bytes calldata b, uint256 p) internal pure returns (uint8 mt, uint64 v, uint256 q) {
        uint8 ib = uint8(b[p]);
        mt = ib >> 5;
        uint8 ai = ib & 31;
        q = p + 1;
        if (ai < 24) v = ai;
        else if (ai == 24) (v, q) = (uint8(b[q]), q + 1);
        else if (ai == 25) (v, q) = (uint16(bytes2(b[q:q + 2])), q + 2);
        else if (ai == 26) (v, q) = (uint32(bytes4(b[q:q + 4])), q + 4);
        else if (ai == 27) (v, q) = (uint64(bytes8(b[q:q + 8])), q + 8);
        else revert Indefinite();
    }

    /// Position just past the item starting at p.
    function skip(bytes calldata b, uint256 p) internal pure returns (uint256) {
        (uint8 mt, uint64 v, uint256 q) = head(b, p);
        if (mt == 2 || mt == 3) return q + v;
        if (mt == 4 || mt == 5) {
            uint256 n = mt == 4 ? v : 2 * uint256(v);
            for (uint256 i; i < n; i++) q = skip(b, q);
            return q;
        }
        if (mt == 6) return skip(b, q);
        return q;
    }

    /// Position of the value stored under a text key in the map at p, or 0 if the key is absent.
    function find(bytes calldata b, uint256 p, bytes memory key) internal pure returns (uint256) {
        (uint8 mt, uint64 n, uint256 q) = head(b, p);
        if (mt != 5) revert WrongType(5, mt);
        bytes32 k = keccak256(key);
        for (uint256 i; i < n; i++) {
            (uint8 kt, uint64 kl, uint256 kq) = head(b, q);
            uint256 vp = skip(b, q);
            if (kt == 3 && kl == key.length && keccak256(b[kq:kq + kl]) == k) return vp;
            q = skip(b, vp);
        }
        return 0;
    }

    function bstr(bytes calldata b, uint256 p) internal pure returns (bytes calldata) {
        return str(b, p, 2);
    }

    function text(bytes calldata b, uint256 p) internal pure returns (bytes calldata) {
        return str(b, p, 3);
    }

    function str(bytes calldata b, uint256 p, uint8 want) private pure returns (bytes calldata) {
        (uint8 mt, uint64 v, uint256 q) = head(b, p);
        if (mt != want) revert WrongType(want, mt);
        return b[q:q + v];
    }

    /// Header bytes for a byte string of length n.
    function bstrHeader(uint256 n) internal pure returns (bytes memory) {
        if (n < 24) return abi.encodePacked(uint8(0x40 | n));
        if (n < 0x100) return abi.encodePacked(uint8(0x58), uint8(n));
        if (n < 0x10000) return abi.encodePacked(uint8(0x59), uint16(n));
        return abi.encodePacked(uint8(0x5a), uint32(n));
    }
}
