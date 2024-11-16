// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../interfaces/UserOperation.sol";
import "../interfaces/IModularAccount.sol";
import "../interfaces/IValidationModule.sol";

library PasskeyAccountStorage {
  using ECDSA for bytes32;

  error PublicKeyAlreadyAdded(bytes publicKey);
  error PublicKeyAlreadyRemoved(bytes publicKey);
  error RemovingTheLastKeyNotAllowed(bytes publicKey);
  error InvalidNonce(uint256 nonce);
  error InvalidSelectors();
  error ValidationAlreadyRemoved(bytes24 moduleEntity);

  event PublicKeyAdded(bytes publicKey); 
  event PublicKeyRemoved(bytes publicKey);
  event UserOpValidationAdded(bytes24 moduleEntity);
  event SignatureValidationAdded(bytes24 moduleEntity);
  event GlobalValidationAdded(bytes24 moduleEntity);
  event UserOpValidationRemoved(bytes24 moduleEntity);
  event SignatureValidationRemoved(bytes24 moduleEntity);
  event GlobalValidationRemoved(bytes24 moduleEntity);
  
  bytes32 constant LAYOUT_STORAGE_SLOT = bytes32(uint256(keccak256("trustwallet.PasskeyAccountStorage.1_0_0")));

  address constant ADDRESS_ANCHOR = address(1);
  bytes24 constant MODULE_ENTITY_ANCHOR = bytes24(uint192(1));
  bytes1 constant VALIDATION_CONFIG_FLAG_USEROP = 0x01;
  bytes1 constant VALIDATION_CONFIG_FLAG_SIGNATURE = 0x02;
  bytes1 constant VALIDATION_CONFIG_FLAG_GLOBAL = 0x04;

  bytes4 constant ERC1271_MAGICVALUE = 0x1626ba7e;

  struct Layout {
    uint256 nonce;
    uint256 keyCount;

    // LinkedList, ANCHOR -> A -> B -> C -> ANCHOR
    mapping(address => address) publicKeyList; 
    
    mapping(bytes24 => bytes24) globalValidationList;
    mapping(bytes24 => bytes24) signatureValidationList;
    mapping(bytes24 => bytes24) userOpValidationList;

    mapping(bytes24 => bytes4[]) validationSelectors;
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

    s.publicKeyList[addrPublicKey] = s.publicKeyList[ADDRESS_ANCHOR];
    s.publicKeyList[ADDRESS_ANCHOR] = addrPublicKey;

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

    address prev = ADDRESS_ANCHOR;
    address cur = s.publicKeyList[ADDRESS_ANCHOR];
    while (cur != ADDRESS_ANCHOR) {
      if (addrPublicKeyToBeRemoved == cur) {

        // Revert if the last key is to be removed.
        if (prev == ADDRESS_ANCHOR && s.publicKeyList[cur] == ADDRESS_ANCHOR) {
          revert RemovingTheLastKeyNotAllowed(publicKeyToBeRemoved);
        }

        s.publicKeyList[prev] = s.publicKeyList[cur];
        delete s.publicKeyList[cur];
        return;
      }

      prev = cur;
      cur = s.publicKeyList[cur];
    }

    emit PublicKeyRemoved(publicKeyToBeRemoved);
  }

  function unpackValidationConfig(ValidationConfig config) internal pure returns (address moduleAddress, bytes4 entityId, bytes1 flags) {
    assembly {
      // 20 bytes for module address
      moduleAddress := mload(add(config, 20))
      // 4 bytes for entity Id
      entityId := mload(add(config, 24))
      // 1 byte for flags
      flags := byte(0, mload(add(config, 25)))
    }
  }

    function unpackModuleEntity(bytes24 moduleEntity) internal pure returns (address moduleAddress, bytes4 entityId) {
    assembly {
      // 20 bytes for module address
      moduleAddress := mload(add(moduleEntity, 20))
      // 4 bytes for entity Id
      entityId := mload(add(moduleEntity, 24))
    }
  }

  // function packModuleEntity(address moduleAddress, bytes4 entityId) internal pure returns (ModuleEntity moduleEntity) {
  //   bytes24 packedData;
  //   assembly {
  //       packedData := or(packedData, shl(96, moduleAddress))
  //       packedData := or(packedData, entityId)
  //   }
  //   moduleEntity = ModuleEntity.wrap(packedData);
  // }

  function addValidation(
    Layout storage s,
    ValidationConfig validationConfig,
    bytes4[] calldata selectors)
  internal {
    if ( selectors.length == 0) {
      revert InvalidSelectors();
    }

    (address moduleAddress, bytes4 entityId, bytes1 flags) = unpackValidationConfig(validationConfig);

    bool isUserOpValidation = (flags & VALIDATION_CONFIG_FLAG_USEROP) > 0;
    bool isSignatureValidation = (flags & VALIDATION_CONFIG_FLAG_SIGNATURE) > 0;
    bool isGlobal = (flags & VALIDATION_CONFIG_FLAG_GLOBAL) > 0;

    bytes24 moduleEntity;
    assembly {
        moduleEntity := or(moduleEntity, shl(32, moduleAddress))
        moduleEntity := or(moduleEntity, entityId)
    }

    if (isUserOpValidation && s.userOpValidationList[moduleEntity] == bytes24(0)) {
      s.globalValidationList[moduleEntity] = s.globalValidationList[MODULE_ENTITY_ANCHOR];
      s.globalValidationList[MODULE_ENTITY_ANCHOR] = moduleEntity;

      emit UserOpValidationAdded(moduleEntity);
    }

    if (isSignatureValidation && s.signatureValidationList[moduleEntity] == bytes24(0)) {
      s.signatureValidationList[moduleEntity] = s.signatureValidationList[MODULE_ENTITY_ANCHOR];
      s.signatureValidationList[MODULE_ENTITY_ANCHOR] = moduleEntity;

      emit SignatureValidationAdded(moduleEntity);
    }

    if (isGlobal && s.userOpValidationList[moduleEntity] == bytes24(0)) {
      s.userOpValidationList[moduleEntity] = s.userOpValidationList[MODULE_ENTITY_ANCHOR];
      s.userOpValidationList[MODULE_ENTITY_ANCHOR] = moduleEntity;

      emit GlobalValidationAdded(moduleEntity);
    }

    if (s.validationSelectors[moduleEntity].length == 0) {
      s.validationSelectors[moduleEntity] = selectors;
    }
    
  }

  function removeValidation(Layout storage s, ModuleEntity validationFunction) internal {
    bytes24 moduleEntity = ModuleEntity.unwrap(validationFunction);

    if (s.validationSelectors[moduleEntity].length == 0) {
        revert ValidationAlreadyRemoved(moduleEntity);
    }
    delete s.validationSelectors[moduleEntity];

    // Remove from userOp validation list
    bytes24 prev = MODULE_ENTITY_ANCHOR;
    bytes24 cur = s.userOpValidationList[MODULE_ENTITY_ANCHOR];
    while (cur != MODULE_ENTITY_ANCHOR) {
      if (moduleEntity == cur) {
        s.userOpValidationList[prev] = s.userOpValidationList[cur];
        delete s.userOpValidationList[cur];
        emit UserOpValidationRemoved(moduleEntity);
        break;
      }

      prev = cur;
      cur = s.userOpValidationList[cur];
    }

    // Remove from global validation list
    prev = MODULE_ENTITY_ANCHOR;
    cur = s.signatureValidationList[MODULE_ENTITY_ANCHOR];
    while (cur != MODULE_ENTITY_ANCHOR) {
      if (moduleEntity == cur) {
        s.signatureValidationList[prev] = s.signatureValidationList[cur];
        delete s.signatureValidationList[cur];
        emit SignatureValidationRemoved(moduleEntity);
        break;
      }

      prev = cur;
      cur = s.signatureValidationList[cur];
    }

    // Remove from global validation list
    prev = MODULE_ENTITY_ANCHOR;
    cur = s.globalValidationList[MODULE_ENTITY_ANCHOR];
    while (cur != MODULE_ENTITY_ANCHOR) {
      if (moduleEntity == cur) {
        s.globalValidationList[prev] = s.globalValidationList[cur];
        delete s.globalValidationList[cur];
        emit GlobalValidationRemoved(moduleEntity);
        break;
      }

      prev = cur;
      cur = s.globalValidationList[cur];
    }
  }

  function validateSignature(Layout storage s, bytes memory signature, bytes32 hash) internal view returns (uint256) {
    address sender = hash.recover(signature);

    for (
      address cur = s.publicKeyList[ADDRESS_ANCHOR];
      cur != ADDRESS_ANCHOR;
      cur = s.publicKeyList[cur]
    ) {
      if (sender == cur) {
        return 0;
      }
    }

    return 1; // SIG_VALIDATION_FAILED
  }

  function validateSignatureWithValidationModule(Layout storage s, bytes memory signature, bytes32 hash) internal view returns (uint256) {
    address sender = hash.recover(signature);

    for (
      bytes24 cur = s.signatureValidationList[MODULE_ENTITY_ANCHOR];
      cur != MODULE_ENTITY_ANCHOR;
      cur = s.signatureValidationList[cur]
    ) {
      (address moduleAddress, bytes4 entityId) = unpackModuleEntity(cur);
      
      bytes4 result = IValidationModule(moduleAddress).validateSignature(
        address(this),
        uint32(entityId),
        sender,
        hash,
        signature
      );

      if (result != ERC1271_MAGICVALUE) {
        return 1; // SIG_VALIDATION_FAILED
      }
    }

    return 0;
  }

  function validateAndUpdateNonce(Layout storage s, UserOperation calldata userOp) internal {
    if (s.nonce++ != userOp.nonce) {
      revert InvalidNonce(userOp.nonce);
    }
  }
}