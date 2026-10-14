// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {WrapperERC20} from "./WrapperERC20.sol";
import {TokenMetadata} from "./libraries/TokenMetadata.sol";


event Wrapped(address indexed underlying, uint256 indexed _id, address wrapper, address indexed to, uint256 amount);
event Unwrapped(address indexed underlying, uint256 indexed _id, address wrapper, address indexed to, uint256 amount);

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
contract WrapperFactory is ReentrancyGuard {
    mapping(address wrapper => address underlying) underlyings;
    mapping(address underlying => address wrapper) wrappers;

    string symbolPreFix;
    string namePreFix;
    string public chainSymbol;
    string public chainName;

    constructor(
        string memory _symbolPreFix,
        string memory _namePreFix,
        string memory _chainSymbol,
        string memory _chainName,
    ) {
        symbolPreFix = _symbolPreFix;
        namePreFix = _namePreFix;
        chainSymbol = _chainSymbol;
        chainName = _chainName;
    }

    // Takes a symbol like USDC -> wtUSDC@eth for example on L1
    // Maybe wt:USDC@eth, wt:USDC:eth
    function _formatTokenSymbol(string memory _baseTokenSymbol) private view returns (string memory) {
        return string.concat(symbolPreFix, _baseTokenSymbol, "@", chainSymbol);
    }

    // Takes a name like "USD Coin " -> "Wrapped Warptoad USD Coin Ethereum"  for example on L1
    function _formatTokenName(string memory _baseTokenName) private view returns (string memory) {
        return string.concat("Wrapped ", namePreFix, " ", _baseTokenName, " ", chainName);
    }

    function _deploy(address _underlying,  Type _type) private returns (address) {
        // TODO switch statement?
        address wrapper;
        if(_type == Type.ERC20) {
            wrapper = address(
                new WrapperERC20(
                    _underlying,
                    _getTokenName(TokenMetadata.nameOf(_underlying)),
                    _formatTokenSymbol(TokenMetadata.symbolOf(_underlying)),
                    TokenMetadata.decimalsOf(_underlying)
                )
            );
        }   
        underlyings[wrapper] = _underlying;
        wrappers[_underlying] = wrapper;     
    }

    function _deposit(address _underlying, address _from, uint256 _amount) {
        IERC20(_underlying).safeTransferFrom(_from, address(this), _amount);
    }

    function _withdraw(address _underlying, address _to, uint256 _amount) {
        IERC20(_underlying).safeTransferFrom(address(this), _to, _amount);
    }

    function _mint(address _wrapper, address _to, uint256 _amount) {
        WarptoadERC20(_wrapper).mint(_to, _amount);
    }

    function _burn(address _wrapper, address _from, uint256 _amount) {
        WarptoadERC20(_wrapper).burn(_from, _amount);
    }


    // WARNING fee on transfer tokens and rebase tokens dont work here and will be INSOLVENT
    function wrap(address _underlying, uint256 _amount, address _to)
        external
        nonReentrant
        returns (address)
    {
        address wrapper = wrappers[_underlying];
        if (wrapper == address(0) ) {
            wrapper = _deploy(_underlying, _type);
        }
        _deposit(_underlying, _from, _amount, _type);s
        _mint(_underlying, _type);

        emit Wrapped(_underlying, wrapper, _to, minted);
        return wrapper;
    }


    function unwrap(address _wrapper, uint256 _amount, address _to)
        external
        nonReentrant
        returns (address)
    { 
        address _underlying = underlyings[_wrapper];
        require(_underlying != address(0), "no underlying token found for this wrapper");

        _burn(_withdraw, address(this), _amount);
        _withdraw(_underlying, _to, _amount);
        
        emit UnWrapped(token, _wrapper, _to, _amount);
        return underlying;
    }


    // TODO make sure to not rely on underlying token is in here to unwrap
    // since some tokens have the same address on multiple chains
    // otherwise you have a accounting headache
    // unshield()

}