// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;


library DCAExecutionModuleStorage {
  struct Layout {
    uint256 nonce; // for validating if a buy action has already done.
    address dex;
    address inToken;
    address outToken;
    uint256 interval;
    uint256 nextBuy;
  }
}