// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../interfaces/UserOperation.sol";

library PasskeyAccountStorage {
  using ECDSA for bytes32;

  error PublicKeyAlreadyAdded(bytes publicKey);
  error PublicKeyAlreadyRemoved(bytes publicKey);
  error InvalidNonce(uint256 nonce);

  event PublicKeyAdded(bytes publicKey);
  event PublicKeyRemoved(bytes publicKey);
  
  bytes32 internal constant LAYOUT_STORAGE_SLOT = bytes32(uint256(keccak256("trustwallet.PasskeyAccountStorage.1_0_0")));

  address internal constant ANCHOR = address(1);
  struct Layout {
    uint256 nonce;
    // mapping(bytes32 => bytes) keyHash2PublicKey;
    mapping(address => address) publicKeyList; // LinkedList, ANCHOR -> A -> B -> C -> ANCHOR
  }



  function layout() internal pure returns (Layout storage s) {
    bytes32 position = LAYOUT_STORAGE_SLOT;
    assembly {
        s.slot := position
    }
  }

  function contractNonce(Layout storage s) internal view returns (uint256) {
    return s.nonce;
  }

  function addPublicKey(Layout storage s, bytes memory newPublicKey) internal {
    address addrPublicKey;
    assembly {
        addrPublicKey := mload(add(newPublicKey, 20)) // Load the last 20 bytes as address
    }

    if (s.publicKeyList[addrPublicKey] != address(0)) {
        revert PublicKeyAlreadyAdded(newPublicKey);
    }

    s.publicKeyList[addrPublicKey] = s.publicKeyList[ANCHOR];
    s.publicKeyList[ANCHOR] = addrPublicKey;

    emit PublicKeyAdded(newPublicKey);
  }

  function removePublicKey(Layout storage s, bytes memory publicKeyToBeRemoved) internal {
    address addrPublicKeyToBeRemoved;
    assembly {
        addrPublicKeyToBeRemoved := mload(add(publicKeyToBeRemoved, 20)) // Load the last 20 bytes as address
    }

    if (s.publicKeyList[addrPublicKeyToBeRemoved] == address(0)) {
        revert PublicKeyAlreadyRemoved(publicKeyToBeRemoved);
    }

    address prev = ANCHOR;
    address cur = s.publicKeyList[ANCHOR];
    while (cur != ANCHOR) {
      if (addrPublicKeyToBeRemoved == cur) {
        s.publicKeyList[prev] = s.publicKeyList[cur];
        delete s.publicKeyList[cur];
        return;
      }

      prev = cur;
      cur = s.publicKeyList[cur];
    }

    emit PublicKeyRemoved(publicKeyToBeRemoved);
  }

  function validateSignature(Layout storage s, bytes memory signature, bytes32 hash) internal view returns (uint256) {
    address recovered = hash.recover(signature);

    for (
      address curPublicKey = s.publicKeyList[ANCHOR];
      curPublicKey != ANCHOR;
      curPublicKey = s.publicKeyList[curPublicKey]
    ) {
      if (recovered == curPublicKey) {
        return 0;
      }
    }

    return 1; // SIG_VALIDATION_FAILED
  }

  function validateAndUpdateNonce(Layout storage s, UserOperation calldata userOp) internal {
    if (s.nonce++ != userOp.nonce) {
      revert InvalidNonce(userOp.nonce);
    }
  }
}