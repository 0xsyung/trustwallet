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
import "../utils/Exec.sol";

/// @notice TODO: implement IModularAccountView
/// @notice TODO: implement Upgradeable proxy
contract PasskeyAccount is
    IModularAccount,
    BaseAccount,
    Initializable,
    ERC1271
{
    using ECDSA for bytes32;
    using PasskeyAccountStorage for PasskeyAccountStorage.Layout;

    error OnlyEntryPoint();
    error OnlyEntryPointOrSelf();
    error ExecutionCallReverted(bytes result);

    event PasskeyAccountInitialized(
        IEntryPoint indexed entryPoint,
        address indexed firstPublicKey
    );

    /// @inheritdoc IModularAccount
    string public constant accountId = "TrustWallet.PasskeyAccount.0_1_0";

    IEntryPoint private immutable _entryPoint;
    

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    // @notice No owner. Only controlled by passkeys.
    function initialize(bytes memory publicKey) external initializer {
        return PasskeyAccountStorage.layout().addPublicKey(publicKey);
    }

    receive() external payable {}

    fallback() external payable {
      if (msg.sender != address(_entryPoint) && msg.sender != address(this)) {
        revert OnlyEntryPointOrSelf();
      }

      if (msg.data.length > 0) {
        //TOOD: run all pre-exection hooks

        bytes4 selector;
        assembly {
            // Load the first 4 bytes of msg.data
            selector := calldataload(0)
        }

        address moduleAddress = PasskeyAccountStorage.layout().getExecutionModuleAddress(selector);

        bool success = Exec.delegateCall(moduleAddress, msg.data, gasleft());
        if (!success) {
          bytes memory result = Exec.getReturnData(2048);
          if (result.length > 0) {
              revert ExecutionCallReverted(result);
          }
        }
      }
    }

    function exe() private {

    }

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
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        return PasskeyAccountStorage.layout().validateUserOpAndUpdateNonce(userOp, userOpHash);
    }

    /// @inheritdoc ERC1271
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) public view override returns (bytes4) {
      uint256 validationData = PasskeyAccountStorage.layout().validateSignature(
          signature,
          hash
      );
      if (validationData != 0) {
        return 0xffffffff;
      }

      return MAGICVALUE;
    }

    /// @inheritdoc BaseAccount
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
      return PasskeyAccountStorage.layout().validateSignature(
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

    /// @inheritdoc IModularAccount
    function execute(address target, uint256 value, bytes calldata data) external payable override returns (bytes memory) {
      _requireFromEntryPoint();
      return _call(target, value, data);
    }

    /// @inheritdoc IModularAccount
    function executeBatch(Call[] calldata calls) external payable override returns (bytes[] memory results) {
      _requireFromEntryPoint();
      uint256 callLength = calls.length;
      results = new bytes[](callLength);
      for (uint256 i; i < callLength; ++i) {
        Call calldata call = calls[i];
        results[i] = _call(call.target, call.value, call.data);
      }
    }

    /// @inheritdoc IModularAccount
    function executeWithRuntimeValidation(
        bytes calldata data,
        bytes calldata authorization
    ) external payable override returns (bytes memory) {
      _requireFromEntryPoint();
    }

    /// @inheritdoc IModularAccount
    /// @notice TODO: installData and hooks are ignored for now.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata,
        bytes[] calldata
    ) external override {
      _requireFromEntryPoint();
      PasskeyAccountStorage.layout().addValidation(
        validationConfig,
        selectors
      );
    }

    /// @inheritdoc IModularAccount
    /// @notice TODO: uninstallData and hookUninstallData are ignored for now.
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata,
        bytes[] calldata
    ) external override {
      _requireFromEntryPoint();
      PasskeyAccountStorage.layout().removeValidation(
        validationFunction
      );
    }

    /// @inheritdoc IModularAccount
    /// @notice TODO: installData is ignored for now.
    function installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata
    ) external override {
      _requireFromEntryPoint();
      PasskeyAccountStorage.layout().addExecution(
        module,
        manifest
      );
    }

    /// @inheritdoc IModularAccount
    /// @notice TODO: uninstallData is ignored for now.
    function uninstallExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata
    ) external override {
      _requireFromEntryPoint();
      PasskeyAccountStorage.layout().removeExecution(
        module,
        manifest
      );
    }
}

