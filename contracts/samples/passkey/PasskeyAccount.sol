// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./ERC1271.sol";
import "../SimpleAccount.sol";
import "./IPasskeyAccount.sol";

contract PasskeyAccount is ERC1271, SimpleAccount, IPasskeyAccount {
    using ECDSA for bytes32;

    uint256 publicKeyCount;
    mapping(bytes32 => bytes) keyHash2PublicKey;
    
    // LinkedList
    mapping(bytes32 => bytes32) keyHashList;

    
    constructor(IEntryPoint anEntryPoint) SimpleAccount(anEntryPoint) {}

    // @notice No owner. Only controlled by passkeys.
    function initialize(bytes memory aPublicKey) external initializer {
        super._initialize(address(0));
        _addPublicKey(aPublicKey);
    }

    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        if (isValidSignature(hash, userOp.signature) == MAGICVALUE) {
            return 0;
        }

        return SIG_VALIDATION_FAILED;
    }

    function addPublicKey(bytes memory newPublicKey) external {
        _requireFromEntryPoint();
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

    function removePublicKey(bytes memory publicKey) external {
        _requireFromEntryPoint();

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
    
    function transferOwnership(bytes memory newOwnerPublicKey) external {
        _requireFromEntryPoint();
        
        // Clear all public keys
        for (bytes32 cur = keyHashList[bytes32(0)]; cur != bytes32(0);) {
            bytes32 temp = keyHashList[cur];
            delete keyHashList[cur];
            delete keyHash2PublicKey[cur];
            cur = temp;
        }

        // Add the first public key of the new owner
        bytes32 keyHash = keccak256(newOwnerPublicKey);
        keyHash2PublicKey[keyHash] = newOwnerPublicKey;

        keyHashList[keyHash] = bytes32(0);
        keyHashList[bytes32(0)] = keyHash;
        
        publicKeyCount = 1;
    }

    /**
     * @notice Verifies that the signer is the owner of the signing contract.
     */
    function isValidSignature(
        bytes32 _hash,
        bytes memory _signature
    ) public override view returns (bytes4) {
        // Validate signatures
        address signer = _hash.recover(_signature);
        for (bytes32 cur = keyHashList[bytes32(0)]; cur != bytes32(0); cur = keyHashList[cur]) {
            if (signer == address(uint160(uint256(keyHashList[cur])))) {
                return MAGICVALUE;
            }
        }

        return 0xffffffff;
    }
}
