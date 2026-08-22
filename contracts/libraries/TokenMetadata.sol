// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @dev Best-effort reads of the optional `name()` / `symbol()` / `decimals()`
 * metadata of an arbitrary token.
 *
 * name() and symbol() are optional for erc-1155 and a handful of pre-EIP-20 tokens (MKR and
 * friends) return `bytes32` instead of `string`. This allows that to be decoded
 * or to default to the token address.
 */
library TokenMetadata {
    /// @dev Used when a token does not expose `decimals()`. Matches the ERC-20 convention.
    uint8 internal constant DEFAULT_DECIMALS = 18;

    /// @dev The underlying's `name()`, or its checksummed address if unreadable.
    function nameOf(address token) internal view returns (string memory) {
        (string memory value, bool ok) = _readString(token, IERC20Metadata.name.selector);
        return ok ? value : Strings.toChecksumHexString(token);
    }

    /// @dev The underlying's `symbol()`, or its checksummed address if unreadable.
    function symbolOf(address token) internal view returns (string memory) {
        (string memory value, bool ok) = _readString(token, IERC20Metadata.symbol.selector);
        return ok ? value : Strings.toChecksumHexString(token);
    }

    /**
     * @dev The underlying's `decimals()`, or {DEFAULT_DECIMALS} if unreadable.
     *
     * Purely a display hint: wrapping is 1:1 in base units, so this value is
     * copied onto the wrapper for wallets to render with and feeds no arithmetic
     * anywhere. A wrong guess misdraws a balance; it cannot mismeasure one.
     */
    function decimalsOf(address token) internal view returns (uint8) {
        (bool ok, bytes memory data) = token.staticcall(abi.encodeCall(IERC20Metadata.decimals, ()));
        if (ok && data.length >= 32) {
            uint256 value = abi.decode(data, (uint256));
            if (value <= type(uint8).max) {
                return uint8(value);
            }
        }
        return DEFAULT_DECIMALS;
    }

    /**
     * @dev Reads a `string`- or `bytes32`-returning getter. `ok` is false when the
     * call reverted, the address has no code, or the value decodes to empty.
     */
    function _readString(address token, bytes4 selector) private view returns (string memory, bool) {
        (bool ok, bytes memory data) = token.staticcall(abi.encodeWithSelector(selector));
        if (!ok) {
            return ("", false);
        }

        // A `string` return is a head-plus-tail encoding, so it never fits in one word.
        // Exactly one word therefore means the legacy `bytes32` encoding.
        if (data.length == 32) {
            return _fromBytes32(abi.decode(data, (bytes32)));
        }

        if (data.length >= 64) {
            string memory value = abi.decode(data, (string));
            return (value, bytes(value).length != 0);
        }

        return ("", false);
    }

    /// @dev Trims a right-padded `bytes32` label back to a string.
    function _fromBytes32(bytes32 raw) private pure returns (string memory, bool) {
        uint256 length = 0;
        while (length < 32 && raw[length] != 0) {
            length++;
        }
        if (length == 0) {
            return ("", false);
        }

        bytes memory value = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            value[i] = raw[i];
        }
        return (string(value), true);
    }
}
