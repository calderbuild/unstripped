// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IContentCredentials} from "../IContentCredentials.sol";

/// Example integration: a feed that labels every post with what the registry knows about its image
/// at the moment it is posted. The label is written by the contract, so the poster cannot drop it.
contract LabeledFeed {
    IContentCredentials public immutable credentials;

    struct Post {
        address author;
        bytes32 imageHash;
        string uri;
        bool hasCredential; // a C2PA signer is on record for these exact bytes
        bool aiGenerated; // and that signer declared the image AI-generated
    }

    Post[] public posts;

    event Posted(uint256 indexed id, address indexed author, bytes32 imageHash, bool hasCredential, bool aiGenerated);

    constructor(IContentCredentials registry) {
        credentials = registry;
    }

    function post(bytes32 imageHash, string calldata uri) external returns (uint256 id) {
        bool known = credentials.isRegistered(imageHash);
        bool ai = known && credentials.isAIGenerated(imageHash);
        id = posts.length;
        posts.push(Post(msg.sender, imageHash, uri, known, ai));
        emit Posted(id, msg.sender, imageHash, known, ai);
    }

    function count() external view returns (uint256) {
        return posts.length;
    }
}
