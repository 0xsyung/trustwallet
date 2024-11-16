// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./UserOperation.sol";

interface IAccountExecute {
  function executeUserOp(UserOperation calldata userOp, bytes32 userOpHash) external;
}