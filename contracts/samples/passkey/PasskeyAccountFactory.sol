// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/proxy/Clones.sol";

import "../../interfaces/IEntryPoint.sol";
import "./PasskeyAccount.sol";

contract PasskeyAccountFactory {
    using Clones for address;

    address public immutable accountImplementation;

    constructor(IEntryPoint entryPoint){
        accountImplementation = address(new PasskeyAccount(entryPoint));
    }

    function createAccount(bytes32 salt, bytes calldata aPublicKey) public returns (PasskeyAccount account) {
        address addr = getAddress(salt);
        if (addr.code.length > 0) {
            return PasskeyAccount(payable(addr));
        }

        account = PasskeyAccount(payable(accountImplementation.cloneDeterministic(salt)));
        account.initialize(aPublicKey);
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(bytes32 salt) public view returns (address) {
        return accountImplementation.predictDeterministicAddress(salt);
    }
}
