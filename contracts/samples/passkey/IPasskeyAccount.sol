// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.17;

import "../../interfaces/IAccount.sol";

/**
 * a Passkey account should expose its own public key.
 */
interface IPasskeyAccount is IAccount {
    error PublicKeyAlreadyAdded(bytes publicKey);

    event PublicKeyAdded(bytes publicKey);
    event PublicKeyRemoved(bytes publicKey);

    function getAllPublicKeys() external view returns (bytes[] memory publicKeys);
}
