// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "../interfaces/IModule.sol";

contract OwnerControlModule is IModule {
    function supportsInterface(
        bytes4 interfaceId
    ) external pure override returns (bool) {
      return (interfaceId == type(IModule).interfaceId);
    }

    function onInstall(bytes calldata data) external override {}

    function onUninstall(bytes calldata data) external override {}

    function moduleId() external pure override returns (string memory) {
      return "trustwallet.OwnerControlModule.1_0_0";
    }
}