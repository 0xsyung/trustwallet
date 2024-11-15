// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.17;

import "./IAccount.sol";
import "./IModularAccount.sol";

/**
 * a Passkey account should expose its own public key.
 */
interface IPasskeyAccount is IAccount, IModularAccount {
    error PublicKeyAlreadyAdded(bytes publicKey);

    event PublicKeyAdded(bytes publicKey);
    event PublicKeyRemoved(bytes publicKey);

    function getAllPublicKeys() external view returns (bytes[] memory publicKeys);
}
