// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// What an application needs to read from the Unstripped registry. `imageHash` is the sha256 of
/// the image file as the user uploads it (a copy with its C2PA metadata stripped hashes to the
/// same value as the signed original).
interface IContentCredentials {
    function isRegistered(bytes32 imageHash) external view returns (bool);
    function isAIGenerated(bytes32 imageHash) external view returns (bool);
}
