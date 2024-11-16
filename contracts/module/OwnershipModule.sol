// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "../interfaces/IValidationModule.sol";

contract OwnershipModule is IValidationModule {

  string public constant moduleId = "TrustWallet.OwnershipModule.0_1_0";

  function supportsInterface(
      bytes4 interfaceId
  ) external pure override returns (bool) {
      return (interfaceId == type(IValidationModule).interfaceId);
  }

  function onInstall(bytes calldata data) external override {}

  function onUninstall(bytes calldata data) external override {}


  function validateUserOp(
      uint32 entityId,
      PackedUserOperation calldata userOp,
      bytes32 userOpHash
  ) external override returns (uint256) {}

  function validateRuntime(
      address account,
      uint32 entityId,
      address sender,
      uint256 value,
      bytes calldata data,
      bytes calldata authorization
  ) external override {}

  function validateSignature(
      address account,
      uint32 entityId,
      address sender,
      bytes32 hash,
      bytes calldata signature
  ) external view override returns (bytes4) {}
}