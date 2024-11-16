// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "../interfaces/IExecutionModule.sol";
import "../interfaces/UserOperation.sol";
import "./DCAExecutionModuleStorage.sol";

contract DCAExecutionModule is IExecutionModule {
  using DCAExecutionModuleStorage for DCAExecutionModuleStorage.Layout;
  
  string public constant moduleId = "TrustWallet.DCAExecutionModule.0_1_0";

  function supportsInterface(
      bytes4 interfaceId
  ) external pure override returns (bool) {
      return (interfaceId == type(IExecutionModule).interfaceId);
  }

  function onInstall(bytes calldata data) external override {
    // TODO: implement
    // 1) decode data into 
    // address dex;
    // address inToken;
    // address outToken;
    // uint256 interval;
    // uint256 nextBuy;
    // 2) set them into storage
  }

  function onUninstall(bytes calldata data) external override {
    // TODO: implement
  }

  function buy(uint256 nonce) external {
    // TODO: implement 
    // 1) check if the nonce has already been used.
    // 2) check if inToken is enough
    // 3) check allowance of inToken
    // 4) execute buy from DEX
    // 5) check if outToken is received correctly.
  }

  function executionManifest()
      external
      pure
      override
      returns (ExecutionManifest memory manifest)
  {
    ManifestExecutionFunction memory buyFunction = ManifestExecutionFunction({
      executionSelector: this.buy.selector,
      skipRuntimeValidation: true,
      allowGlobalValidation: false
    });

    manifest.executionFunctions[0] = buyFunction;
  }
}