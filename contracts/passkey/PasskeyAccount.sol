// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "../interfaces/IModularAccount.sol";
import "./ERC1271.sol";
import "./PasskeyAccountStorage.sol";

import "../core/BaseAccount.sol";

contract PasskeyAccount is
    IModularAccount,
    BaseAccount,
    Initializable,
    ERC1271
{
    using ECDSA for bytes32;
    using PasskeyAccountStorage for PasskeyAccountStorage.Layout;

    error OnlyEntryPoint();
    event PasskeyAccountInitialized(
        IEntryPoint indexed entryPoint,
        address indexed firstPublicKey
    );

    IEntryPoint private immutable _entryPoint;

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    // @notice No owner. Only controlled by passkeys.
    function initialize(bytes memory publicKey) external initializer {
        return PasskeyAccountStorage.layout().addPublicKey(publicKey);
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    /// @inheritdoc BaseAccount
    function nonce() public view override returns (uint256) {
        return PasskeyAccountStorage.layout().contractNonce();
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @inheritdoc BaseAccount
    function _validateAndUpdateNonce(
        UserOperation calldata userOp
    ) internal override {
        PasskeyAccountStorage.layout().validateAndUpdateNonce(userOp);
    }

    /// @inheritdoc ERC1271
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) public view override returns (bytes4 magicValue) {
        if (PasskeyAccountStorage.layout().validateSignature(signature, hash) == 0) {
            return MAGICVALUE;
        }

        return 0xffffffff;
    }

    /// @inheritdoc BaseAccount
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        return
            PasskeyAccountStorage.layout().validateSignature(
                userOp.signature,
                userOpHash
            );
    }

    function _call(
        address target,
        uint256 value,
        bytes memory data
    ) internal returns (bytes memory) {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }

        return result;
    }

    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external payable returns (bytes memory) {
        _requireFromEntryPoint();
        return _call(dest, value, func);
    }

    function executeBatch(
        address[] calldata dest,
        bytes[] calldata func
    ) external {
        _requireFromEntryPoint();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    function executeBatch(
        Call[] calldata calls
    ) external payable override returns (bytes[] memory) {}

    function executeWithRuntimeValidation(
        bytes calldata data,
        bytes calldata authorization
    ) external payable override returns (bytes memory) {}

    function installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata installData
    ) external override {}

    function uninstallExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata uninstallData
    ) external override {}

    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external override {}

    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) external override {}

    function accountId() external view override returns (string memory) {}
}

