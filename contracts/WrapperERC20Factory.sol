// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {WrapperERC20} from "./WrapperERC20.sol";
import {TokenMetadata} from "./libraries/TokenMetadata.sol";
import {IWrapperFactory} from "./interfaces/IWrapperFactory.sol";
import {IWarptoad} from "./interfaces/IWarptoad.sol";

import {keccak31Byte} from "./Warptoad.sol";

// TODO rename wrapper factory in warptoad.sol and i protocol to token factory or token minter.
// you can also make a warptoad native token so you never need to deal with wrapping
// this contract obviously is a wrapper tho!
event Wrapped(
    address indexed underlying,
    address wrapper,
    address indexed to,
    uint256 amount
);
event UnWrapped(
    address indexed underlying,
    address wrapper,
    address indexed to,
    uint256 amount
);

/**
 * this guy stores underlying tokens and creates new wrapper tokens
 * @title
 * @author
 * @notice WARNING ONLY DEPLOY WITH CREATE2
 * To unshield the token crosschain, an immutableWrapperFactory needs to be there on the other chain
 * at the SAME ADDRESS. With CREATE2 this is easy to ensure.
 * With regular CREATE from EOA it's easy to fuck up,
 * regular CREATE from contract and bad actors can STEAL FUNDS.
 * Exactly like in the wintermute incident on optmism, but then here every user will be effected
 */
contract WrapperFactory is IWrapperFactory, ReentrancyGuard {
    using SafeERC20 for IERC20;

    struct Underlying {
        address contractAddr;
        uint64 gigaIndex;
    }

    struct UnderlyingInfo {
        string name;
        string symbol;
        uint256 decimals;
    }
    // added gigaIndex because technically token can be deployed to the same address on multiple chains
    mapping(address underlying => mapping (uint64 gigaIndex => address wrapper)) wrappers;
    mapping(address wrapper => Underlying underlying) underlyings;


    string symbolPreFix;
    string namePreFix;
    string public chainSymbol;
    string public chainName;

    address immutable warptoad;
    uint64 immutable gigaIndex;

    error OnlyWarptoad(address inCorrectCaller);

    constructor(
        string memory _symbolPreFix,
        string memory _namePreFix,
        string memory _chainSymbol,
        string memory _chainName,
        address _warptoad
    ) {
        symbolPreFix = _symbolPreFix;
        namePreFix = _namePreFix;
        chainSymbol = _chainSymbol;
        chainName = _chainName;
        warptoad = _warptoad;
        gigaIndex= IWarptoad(warptoad).gigaIndex();
    }

    // Takes a symbol like USDC -> wtUSDC@eth for example on L1
    // Maybe wt:USDC@eth, wt:USDC:eth
    function _formatTokenSymbol(
        string memory _baseTokenSymbol
    ) private view returns (string memory) {
        return string.concat(symbolPreFix, _baseTokenSymbol, "@", chainSymbol);
    }

    // Takes a name like "USD Coin " -> "Wrapped Warptoad USD Coin Ethereum"  for example on L1
    function _formatTokenName(
        string memory _baseTokenName
    ) private view returns (string memory) {
        return
            string.concat(
                "Wrapped ",
                namePreFix,
                " ",
                _baseTokenName,
                " ",
                chainName
            );
    }

    function getUnderlyingInfo(
        address _underlying
    ) public view returns (UnderlyingInfo memory) {
        return
            UnderlyingInfo(
                _formatTokenName(TokenMetadata.nameOf(_underlying)),
                _formatTokenSymbol(TokenMetadata.symbolOf(_underlying)),
                TokenMetadata.decimalsOf(_underlying)
            );
    }

    function _deploy(
        address _underlying,
        uint64 _gigaIndex,
        UnderlyingInfo memory
    ) private returns (address) {
        // CREATE2 so the wrapper lands on the same address on every chain this factory is deployed on.
        // The address commits to the init code, so to all constructor args. That is what makes
        // `_deployedWrapper == _wrapper` in unShield actually verify the args. Salt can be constant
        // TODO switch statement?
        address _wrapper = address(
            new WrapperERC20{salt: bytes32(0)}(
                _underlying,
                _gigaIndex,
                _formatTokenName(TokenMetadata.nameOf(_underlying)),
                _formatTokenSymbol(TokenMetadata.symbolOf(_underlying)),
                TokenMetadata.decimalsOf(_underlying)
            )
        );
        underlyings[_wrapper] = Underlying({
            contractAddr: _underlying,
            gigaIndex: _gigaIndex
        });
        wrappers[_underlying][_gigaIndex] = _wrapper;
        return _wrapper;
    }

    function _deposit(
        address _underlying,
        address _from,
        uint256 _amount
    ) private {
        IERC20(_underlying).safeTransferFrom(_from, address(this), _amount);
    }

    function _withdraw(
        address _underlying,
        address _to,
        uint256 _amount
    ) private {
        IERC20(_underlying).safeTransfer(_to, _amount);
    }

    function _mint(address _wrapper, address _to, uint256 _amount) private {
        WrapperERC20(_wrapper).mint(_to, _amount);
    }

    function _burn(address _wrapper, address _from, uint256 _amount) private {
        WrapperERC20(_wrapper).burn(_from, _amount);
    }

    // WARNING fee on transfer tokens and rebase tokens dont work here and will be INSOLVENT
    function wrap(
        address _underlying,
        uint256 _amount,
        address _to
    ) external nonReentrant returns (address) {
        uint64 _gigaIndex = gigaIndex;
        address _wrapper = wrappers[_underlying][_gigaIndex];
        if (_wrapper == address(0)) {
            _wrapper = _deploy(
                _underlying,
                _gigaIndex,
                getUnderlyingInfo(_underlying)
            );
        }
        _deposit(_underlying, msg.sender, _amount);
        _mint(_wrapper, _to, _amount);

        emit Wrapped(_underlying, _wrapper, _to, _amount);
        return _wrapper;
    }

    function unWrap(
        address _wrapper,
        uint256 _amount,
        address _to
    ) external nonReentrant returns (address) {
        Underlying memory _underlying = underlyings[_wrapper];
        require(
            _underlying.contractAddr != address(0),
            "no underlying token found for this wrapper"
        );
        require(_underlying.gigaIndex == gigaIndex, "only unwrap on the same wrapperFactory on the same chain/gigaIndex");

        _burn(_wrapper, msg.sender, _amount);
        _withdraw(_underlying.contractAddr, _to, _amount);

        emit UnWrapped(_underlying.contractAddr, _wrapper, _to, _amount);
        return _underlying.contractAddr;
    }

    function _decodeAssetArgs(
        bytes memory _wrapperArgs
    ) public pure returns (address, address) {
        // Some tokens are deployed to the same address on multiple chains.
        // And since the accounting of our wrapperFactory only stores underlying tokens on one chain,
        // only checking `_underlying` address can cause unexpected scenerarios where users cant unwrap!

        // so we differentiate on which gigaIndex a token was wrapped to enforce "only unwrap on one chain (aka gigaIndex)"
        // that is what`_wrappingOrginIndex` is for. I does not doxx where a user came from and shielded.

        // TODO shrink _wrappingOrginIndex to smaller size then 256

        // both _wrappeer and _underlying here to save on a expensive mapping lookup!
        (address _wrapper, address _underlying) = abi.decode(
            _wrapperArgs,
            (address, address)
        );
        return (_wrapper, _underlying);
    }

    function _decodeWrapperInfo(
        bytes memory _wrapperArgs
    ) private pure returns (UnderlyingInfo memory, uint64) {
        // TODO can we save a bit of gas by making _decodeAssetArgs return the left over bytes?
        // then decoding those so we dont spend on the 2 addresses?
        (
            ,
            ,
            string memory _name,
            string memory _symbol,
            uint256 _decimals,
            uint64 _gigaIndex
        ) = abi.decode(
                _wrapperArgs,
                (address, address, string, string, uint256, uint64)
            );
        return (UnderlyingInfo(_name, _symbol, _decimals), _gigaIndex);
    }

    function _hashArgs(
        bytes memory _wrapperArgs
    ) public pure returns (uint256) {
        return keccak31Byte(_wrapperArgs);
    }

    modifier onlyWarptoad() {
        if (msg.sender != warptoad) {
            revert OnlyWarptoad(msg.sender);
        }
        _;
    }

    function shield(
        address _from,
        uint256 _amount,
        bytes memory _args
    ) external onlyWarptoad returns (uint256) {
        uint256 _argsHash = _hashArgs(_args);
        (address _wrapper, ) = _decodeAssetArgs(_args);
        _burn(_wrapper, _from, _amount);
        return _argsHash;
    }

    function unShield(
        address _recipient,
        uint256 _amount,
        bytes memory _args
    ) external onlyWarptoad returns (uint256) {
        uint256 _argsHash = _hashArgs(_args);
        (address _wrapper, address _underlying) = _decodeAssetArgs(_args);
        // wrapper does not exist it always means it was bridged. And the orginal underlying is on another chain
        if (_wrapper.code.length == 0) {
            (
                UnderlyingInfo memory underlyingInfo,
                uint64 _gigaIndex
            ) = _decodeWrapperInfo(_args);
            address _deployedWrapper = _deploy(
                _underlying,
                _gigaIndex,
                underlyingInfo
            );
            require(
                _deployedWrapper == _wrapper,
                "deployed wrapper does not match expected wrapper from assetId, please make sure _wrapperArgs contains exactly `_name,  _symbol, _decimals, _gigaIndex` of the wrapper on the orginal chain"
            );
        }
        _mint(_wrapper, _recipient, _amount);
        return _argsHash;
    }
    // TODO make sure to not rely on underlying token is in here to unwrap
    // since some tokens have the same address on multiple chains
    // otherwise you have a accounting headache
    // unshield()
}
