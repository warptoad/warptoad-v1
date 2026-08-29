// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {WarptoadERC20} from "./WarptoadERC20.sol";
import {WarptoadERC1155} from "./WarptoadERC1155.sol";
import {TokenMetadata} from "./libraries/TokenMetadata.sol";

import {
    SkinnyIMTPoseidon2WriteStorage,
    SkinnyIMTDataStorage
} from "@warptoad/skinny-imt.sol/poseidon2/SkinnyIMTPoseidon2WriteStorage.sol";
//import {SkinnyIMTDataEvent} from "@warptoad/skinny-imt.sol/poseidon2/SkinnyIMTPoseidon2WriteEvent.sol";
import {SkinnyIMTPoseidon2Read} from "@warptoad/skinny-imt.sol/poseidon2/SkinnyIMTPoseidon2Read.sol";
import {SkinnyIMTReadableStorage} from "@warptoad/skinny-imt.sol/SkinnyIMTReadableStorage.sol";

import {Poseidon2} from "poseidon2-evm/src/bn254/Poseidon2.sol";

enum AssetType {
    ERC20,
    ERC721,
    ERC1155
}

/**
 * @title Warptoad
 * @author Jim Jim Valkema, nodestarQ
 * @notice does NOT support rebasing tokens!
 */
contract Warptoad is ERC1155Holder, ReentrancyGuard, SkinnyIMTReadableStorage {
    using SafeERC20 for IERC20;
    
    SkinnyIMTDataStorage commitmentTree;

    string symbolPreFix;
    string namePreFix;
    string public chainSymbol;
    string public chainName;
    uint64 public immutable gigaIndex;

    /// @notice Wrapper token deployed for an underlying ERC-20, or zero if never wrapped.
    mapping(address underlying => address wrapper) public erc20WrapperOf;

    /// @notice Wrapper collection deployed for an underlying ERC-1155, or zero if never wrapped.
    mapping(address underlying => address wrapper) public erc1155WrapperOf;

    struct Underlying {
        address token;
        // not actually chainId, chainId changes when forking, causing user only able to unshield on the chain that did not fork
        uint64 chainWarpDomain;
    }

    /// @notice Underlying a wrapper redeems for. Non-zero exactly for tokens this vault deployed.
    mapping(address wrapper => Underlying underlying) public underlyingOf;

    /// @notice underlying tokens where wrapping is blocked (unwrapping is always allowed), only constructor and closeUndercollateralizedPool can add
    mapping(address underlying => bool closed) public closedPools;

    event ERC20WrapperCreated(address indexed underlying, address indexed wrapper);
    event ERC1155WrapperCreated(address indexed underlying, address indexed wrapper);
    event ERC20Wrapped(address indexed underlying, address indexed wrapper, address indexed to, uint256 amount);
    event ERC20Unwrapped(address indexed underlying, address indexed wrapper, address indexed to, uint256 amount);
    event ERC1155Wrapped(
        address indexed underlying, address indexed wrapper, address indexed to, uint256 id, uint256 amount
    );
    event ERC1155Unwrapped(
        address indexed underlying, address indexed wrapper, address indexed to, uint256 id, uint256 amount
    );

    /// @notice asset is no longer allowed to be wrapped (unwrapping allowed)
    event PoolClosed(address indexed underlying);

    /// @dev Thrown when unwrapping a token this vault did not issue, or issued for the other standard.
    error NotAWrapper(address token);
    /// @dev Thrown when wrapping an underlying whose pool is closed. Unwrapping it still works.
    error PoolIsClosed(address token);
    error ZeroAmount();
    error ZeroAddress();
    error WrongTreeId();

    /**
     *
     * @param _symbolPreFix: shortened name of the chain this contract is deployed on, used for wrapper symbol
     * @param _namePreFix: shortened name of the chain this contract is deployed on, used for wrapper symbol
     * @param _chainSymbol: shortened name of the chain this contract is deployed on, used for wrapper symbol
     * @param _chainName: shortened name of the chain this contract is deployed on, used for wrapper symbol
     * @param _gigaIndex:
     * @param _blockedTokens blocks these tokes from every being wrapped. Meant for rebasing tokens who can break solvency.
     * @notice don't worry: can only be done at constructor or if a rebase token is detected (with closeUndercollateralizedPool)
     * and you can always unwrap :D
     */
    constructor(
        string memory _symbolPreFix,
        string memory _namePreFix,
        string memory _chainSymbol,
        string memory _chainName,
        uint64 _gigaIndex,
        address[] memory _blockedTokens
    ) {
        symbolPreFix = _symbolPreFix;
        namePreFix = _namePreFix;
        chainSymbol = _chainSymbol;
        chainName = _chainName;
        gigaIndex = _gigaIndex;

        for (uint256 i = 0; i < _blockedTokens.length; i++) {
            closedPools[_blockedTokens[i]] = true;
            emit PoolClosed(_blockedTokens[i]);
        }

        SkinnyIMTPoseidon2WriteStorage.init(commitmentTree);
    }

    // ------ SkinnyIMT overrides -----------
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(SkinnyIMTReadableStorage, ERC1155Holder)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function commitmentTreeId() public view returns (uint256) {
        return commitmentTree.treeData.treeId;
    }

    function _getSkinnyStorageTree(uint256 treeId) internal view override returns (SkinnyIMTDataStorage storage) {
        if (treeId != commitmentTree.treeData.treeId) {
            revert WrongTreeId();
        }
        return commitmentTree;
    }
    //--------------------------------------

    /**
     * @notice public to save debugging headaches for sdk
     * @param contractAddr:
     * @param id:
     * @param originGigaIndex:
     * @param assetType:
     */
    function assetId(
        address contractAddr,
        uint256 id, // 0 for ERC20
        uint256 originGigaIndex,
        AssetType assetType
    ) public pure returns (uint256) {
        // >> 8 drops last byte so we fit in a 254 field!
        return uint256(keccak256(abi.encode(contractAddr, id, originGigaIndex, assetType))) >> 8;
    }

    //--------- shielding -----------
    /**
     * @param _wrapper: which wrapped token to shield
     * @param _amount: how much to shield
     * @param _preCommitmentHash: who will receive the shielded tokens, as a blinded hash
     */
    function shieldErc20(address _wrapper, uint256 _amount, uint256 _preCommitmentHash) public {
        address token = underlyingOf[_wrapper].token;
        if (token == address(0) || erc20WrapperOf[token] != _wrapper) revert NotAWrapper(_wrapper);
        // burn it, it is now shielded and can be unshielded on this or another chain, where a new wrapper token is minted :D
        WarptoadERC20(_wrapper).burn(msg.sender, _amount);
        uint256 _assetId = assetId(token, 0, gigaIndex, AssetType.ERC20);
        // @notice, zemse poseidon implementation can only handle up to 3 inputs, transferDataHash is just to get around that
        uint256 _commitment = Poseidon2.hash_3(_preCommitmentHash, _assetId, _amount);
        SkinnyIMTPoseidon2WriteStorage.insert(commitmentTree, _commitment);
    }

    function unshieldErc20(address _wrapper, uint256 _amount, address _recipient) public {
        // address token = underlyingOf[_wrapper].token;
        // if (token == address(0) || erc20WrapperOf[token] != _wrapper) revert NotAWrapper(_wrapper);
        // // verify proof
        // // public inputs like amount, wrapper address, recipient,

        // WarptoadERC20(_wrapper).mint(_recipient, _amount);
    }

    //----------------------------

    // Takes a symbol like USDC -> wtUSDC@eth for example on L1
    // Maybe wt:USDC@eth, wt:USDC:eth
    function _getTokenSymbol(string memory _baseTokenSymbol) private view returns (string memory) {
        return string.concat(symbolPreFix, _baseTokenSymbol, "@", chainSymbol);
    }

    // Takes a name like "USD Coin " -> "Wrapped Warptoad USD Coin Ethereum"  for example on L1
    function _getTokenName(string memory _baseTokenName) private view returns (string memory) {
        return string.concat("Wrapped ", namePreFix, " ", _baseTokenName, " ", chainName);
    }

    // --- ERC-20 wrapping ---------------------------------------------------------------

    /**
     * `_amount` is deposited here and `_to` receives wrapped token as claim on this deposit
     * @notice Creates a new wrapper token contract from a openzeppelin clone factory
     * if it does not exist yet
     * @return wrapper The wrapper token minted.
     * @return minted Amount minted, which can differ from _amount on some tokens
     * like fee on transfer tokens.
     */
    function wrapERC20(address _token, uint256 _amount, address _to)
        external
        nonReentrant
        returns (address wrapper, uint256 minted)
    {
        if (closedPools[_token]) revert PoolIsClosed(_token);

        wrapper = _getOrCreateERC20Wrapper(_token);

        // Check before balance to deal with fee on transfer tokens causing insolvency
        uint256 balanceBefore = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        minted = IERC20(_token).balanceOf(address(this)) - balanceBefore;

        WarptoadERC20(wrapper).mint(_to, minted);
        emit ERC20Wrapped(_token, wrapper, _to, minted);
    }

    /**
     * @notice Burns `_amount` of `_wrapper` from the caller and releases the same
     * amount of underlying collateral to `_to`.
     * @return token The underlying released.
     */
    function unwrapERC20(address _wrapper, uint256 _amount, address _to)
        external
        nonReentrant
        returns (
            address token // @TODO no definitions in returns. It's a foot gun jimjim fucks up a lott
        )
    {
        token = underlyingOf[_wrapper].token;
        if (token == address(0) || erc20WrapperOf[token] != _wrapper) revert NotAWrapper(_wrapper);

        WarptoadERC20(_wrapper).burn(msg.sender, _amount);
        IERC20(token).safeTransfer(_to, _amount);

        emit ERC20Unwrapped(token, _wrapper, _to, _amount);
    }

    /**
     * automatically deploy a wrapper contract clone if it does not exist yet
     * @param _token which underlying to wrap
     */
    function _getOrCreateERC20Wrapper(address _token) private returns (address wrapper) {
        wrapper = erc20WrapperOf[_token];
        if (wrapper != address(0)) return wrapper;

        // deploy the contract
        wrapper = address(
            new WarptoadERC20(
                _token,
                _getTokenName(TokenMetadata.nameOf(_token)),
                _getTokenSymbol(TokenMetadata.symbolOf(_token)),
                TokenMetadata.decimalsOf(_token)
            )
        );

        erc20WrapperOf[_token] = wrapper;
        underlyingOf[wrapper] = Underlying({token: _token, chainWarpDomain: gigaIndex});
        emit ERC20WrapperCreated(_token, wrapper);
    }

    // is cute but wrapper tokens get burned upon shielding and get minted on different chains
    // so not a valid detection mechanism, but it might be possible if we swap out `WarptoadERC20(wrapper).totalSupply`
    // for another counter
    // function closeUndercollateralizedPool(address _token) external returns (bool closed) {
    //     address wrapper = erc20WrapperOf[_token];
    //     if (wrapper == address(0)) revert NotAWrapper(_token);
    //
    //     if (IERC20(_token).balanceOf(address(this)) >= WarptoadERC20(wrapper).totalSupply()) {
    //         return false;
    //     }
    //
    //     poolIsClosed[_token] = true;
    //     emit PoolClosed(_token);
    //     return true;
    // }

    // --- ERC-1155  wrapping -------------------------------------------------------------

    /**
     * TODO 721 just support wrapping by default.
     * `_amount` of the `_id` is deposited here and _to receives wrapped token as claim on this deposit
     * @notice Creates a new wrapper token contract from a openzeppelin clone factory
     * if it does not exist yet
     * @return wrapper The wrapper collection minted.
     */
    function wrapERC1155(address _collection, uint256 _id, uint256 _amount, address _to)
        external
        nonReentrant
        returns (address wrapper)
    {
        if (closedPools[_collection]) revert PoolIsClosed(_collection);

        wrapper = _getOrCreateERC1155Wrapper(_collection);

        IERC1155(_collection).safeTransferFrom(msg.sender, address(this), _id, _amount, "");
        WarptoadERC1155(wrapper).mint(_to, _id, _amount);

        emit ERC1155Wrapped(_collection, wrapper, _to, _id, _amount);
    }

    //wrapERC721

    /**
     * @notice Burns `_amount` of `_wrapper`'s token `_id` from the caller and
     * releases the underlying collateral to `_to`.
     * @return collection The underlying collection released.
     */
    function unwrapERC1155(address _wrapper, uint256 _id, uint256 _amount, address _to)
        external
        nonReentrant
        returns (address collection)
    {
        collection = underlyingOf[_wrapper].token;
        if (collection == address(0) || erc1155WrapperOf[collection] != _wrapper) revert NotAWrapper(_wrapper);

        WarptoadERC1155(_wrapper).burn(msg.sender, _id, _amount);
        IERC1155(collection).safeTransferFrom(address(this), _to, _id, _amount, "");

        emit ERC1155Unwrapped(collection, _wrapper, _to, _id, _amount);
    }

    /**
     * @dev ERC-1155 has no standard name/symbol, so both are read best-effort from
     * the collection and fall back to its address.
     */
    function _getOrCreateERC1155Wrapper(address _collection) private returns (address wrapper) {
        wrapper = erc1155WrapperOf[_collection];
        if (wrapper != address(0)) return wrapper;

        wrapper = address(
            new WarptoadERC1155(
                _collection,
                _getTokenName(TokenMetadata.nameOf(_collection)),
                _getTokenSymbol(TokenMetadata.symbolOf(_collection))
            )
        );

        erc1155WrapperOf[_collection] = wrapper;
        underlyingOf[wrapper] = Underlying({token: _collection, chainWarpDomain: gigaIndex});
        emit ERC1155WrapperCreated(_collection, wrapper);
    }
}
