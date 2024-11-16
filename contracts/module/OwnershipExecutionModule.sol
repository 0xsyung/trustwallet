// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "../interfaces/IExecutionModule.sol";
import "../interfaces/UserOperation.sol";
import "../passkey/PasskeyAccountStorage.sol";

contract OwnershipExecutionModule is IExecutionModule {
  using PasskeyAccountStorage for PasskeyAccountStorage.Layout;
  
  string public constant moduleId = "TrustWallet.OwnershipModule.0_1_0";

  function supportsInterface(
      bytes4 interfaceId
  ) external pure override returns (bool) {
      return (interfaceId == type(IExecutionModule).interfaceId);
  }

  function onInstall(bytes calldata data) external override {
    // TODO: implement
  }

  function onUninstall(bytes calldata data) external override {
    // TODO: implement
  }

  function transferOwnership(bytes memory newPublicKey) external {
    PasskeyAccountStorage.layout().resetPublicKeyList(newPublicKey);
  }

  function executionManifest()
      external
      pure
      override
      returns (ExecutionManifest memory manifest)
  {
    ManifestExecutionFunction memory transferOwnershipFunction = ManifestExecutionFunction({
      executionSelector: this.transferOwnership.selector,
      skipRuntimeValidation: true,
      allowGlobalValidation: false
    });

    manifest.executionFunctions[0] = transferOwnershipFunction;
  }
}