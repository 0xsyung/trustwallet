// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../SimpleAccount.sol";
import "./IPasskeyAccount.sol";

contract PasskeyAccount is SimpleAccount, IPasskeyAccount {
    using ECDSA for bytes32;

    uint256 publicKeyCount;
    mapping(bytes32 => bytes) keyHash2PublicKey;
    
    // LinkedList
    mapping(bytes32 => bytes32) keyHashList;

    
    constructor(IEntryPoint anEntryPoint) SimpleAccount(anEntryPoint) {}

    function initialize(bytes memory aPublicKey) public initializer {
        super._initialize(address(0));
        _addPublicKey(aPublicKey);
    }

    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address signer = hash.recover(userOp.signature);

        for (bytes32 cur = keyHashList[bytes32(0)]; cur != bytes32(0); cur = keyHashList[cur]) {
            if (signer == address(uint160(uint256(keyHashList[cur])))) {
                return 0;
            }
        }

        return SIG_VALIDATION_FAILED;
    }

    function addPublicKey(bytes memory newPublicKey) public onlyOwner {
        _addPublicKey(newPublicKey);
    }

    function _addPublicKey(bytes memory newPublicKey) internal {
        bytes32 keyHash = keccak256(newPublicKey);
        if (keyHashList[keyHash] == bytes32(0)) {
            revert PublicKeyAlreadyAdded(newPublicKey);
        }

        keyHash2PublicKey[keyHash] = newPublicKey;

        keyHashList[keyHash] = keyHashList[bytes32(0)];
        keyHashList[bytes32(0)] = keyHash;

        ++publicKeyCount;

        emit PublicKeyAdded(newPublicKey);
    }

    function removePublicKey(bytes memory publicKey) public onlyOwner {
        bytes32 keyHash = keccak256(publicKey);
        bytes32 prev = bytes32(0);
        bytes32 cur = keyHashList[bytes32(0)];
        while (cur != bytes32(0)) {
            if (cur == keyHash) {
                keyHashList[prev] = keyHashList[cur];
                delete keyHashList[cur];
                --publicKeyCount;
                return;
            }
            prev = cur;
            cur = keyHashList[cur];
        }
    }

    /// @inheritdoc IPasskeyAccount
    function getAllPublicKeys() external view override returns (bytes[] memory publicKeys) {
        publicKeys = new bytes[](publicKeyCount);
        uint256 index;
        for (bytes32 cur = keyHashList[bytes32(0)]; cur != bytes32(0); cur = keyHashList[cur]) {
            publicKeys[index] = keyHash2PublicKey[cur];
            ++index;
        }
    }
}
