# warptoad-v1  
The next itteration of the PoC here https://github.com/warptoad/warp-toad  
Build in noir but with a potential circom rewrite in mind, with no proof recursion.  
   
Some of the new privacy features are:
- **swaptoad**: shielded swaps
- **nulltoad**: makes commitments spendable on pending roots
- **swaptoad**

New techincal features:
- **nft support** *(1155/721)*:
- **modular wrappers**: 
- **permissionless gigabridge**:
- **jubjub signature**

## Contracts

```sh
pnpm install
pnpm compile   # hardhat compile
pnpm test      # hardhat test
pnpm size      # contract size report
```

### Deploy + verify on Sepolia

Secrets go in the hardhat keystore once (plain env vars with the same names also work):

```sh
npx hardhat keystore set SEPOLIA_RPC_URL
npx hardhat keystore set SEPOLIA_PRIVATE_KEY
npx hardhat keystore set ETHERSCAN_API_KEY
```

deploy with ignition

```sh
pnpm noir             # if the circuit changed: new verifier, Warptoad has it as an immutable
pnpm deploy:sepolia   # ignition deploy + etherscan verify, always a fresh set of contracts
```
TODO remove this, claude freaks out here for no reason!
`deploy:sepolia` runs with `--reset`: it wipes `ignition/deployments/chain-11155111` and deploys everything again.
Ignition does not notice that bytecode changed for a future it already completed, so without the reset a changed
verifier or Warptoad would silently keep the old addresses. If a deploy stopped halfway (stuck tx, out of gas) and
you want to pick it up where it left off instead, use `pnpm deploy:sepolia:resume`.

Nothing chain specific goes in: ChainConfig gets the whole table from `src/config.ts` and the contracts read their
own giga index from it by `block.chainid`. The only parameter, in `ignition/parameters/sepolia.json`, is the address
of the SkinnyIMT library, which is the same CREATE2 address on every chain. Commit the new `ignition/deployments`
folder, the sepolia test run reads the addresses from it

Wrapper tokens are deployed by `WrapperFactory` on first wrap, so they might not be automatically
verified. In case you need one verified do:

```sh
pnpm verify:wrapper:sepolia 0xfc632092084235675bebe56263976397959a0ff7
```

Run test on sepolia
```sh
pnpm hardhat run test/ClaudeLilMessaging.test.ts --network sepolia
```

## Circuits

### Install Noir

```sh
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup -v 1.0.0-beta.22

curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
bbup    # picks the bb release matching your nargo

source ~/.bashrc
nargo --version   # 1.0.0-beta.22
bb --version      # 5.0.0-nightly.20260522
```

Use beta.22: newer nargo compiles fine, but
[bbup's version map](https://github.com/AztecProtocol/aztec-packages/blob/next/barretenberg/bbup/bb-versions.json)
has no `bb` for anything past it.

### Build

```sh
pnpm noir;
pnpm hardhat compile;
```

## aztec-nargo conflicts

Aztec ships its own nargo and puts it ahead of yours, so `nargo --version` shows
a version you never installed (`which -a nargo` shows who wins). We don't use
Aztec here — remove it, then reinstall Noir:

```sh
sudo rm -f /usr/local/bin/nargo /usr/local/bin/aztec
rm -rf ~/.aztec
```

## Gas

`pnpm hardhat test test/ClaudeLilMessaging.test.ts --gas-stats`, CIRCUIT_SIZE 4:

| | gas |
| --- | --- |
| `WarptoadVerifier.verify` on its own (8.7 KB proof, 30 public inputs) | ~875k, ~150k of that is calldata |
| `verifyShieldedTx` (1 spend, 1 unshield, 3 tree inserts) | ~1.37M |
| `shieldErc20` | ~211k |
| `wrapERC20` first time (deploys the wrapper) | ~756k |
| deploy `Warptoad` / `WarptoadVerifier` | 5.5M / 3.6M |


# deployments

warptoad: [0x32572A5bAd031B37A260ccDCBd8F2533181f4B61](https://sepolia.etherscan.io/address/0x32572A5bAd031B37A260ccDCBd8F2533181f4B61)  
wrapperFactory: [0xc7DaF4234ADee80c054C6dD93b8a3DA0E2BD2685](https://sepolia.etherscan.io/address/0xc7DaF4234ADee80c054C6dD93b8a3DA0E2BD2685)  
verifier: [0xC5F6941835866d1FbEFB7E6767B2C853941CCBA8](https://sepolia.etherscan.io/address/0xC5F6941835866d1FbEFB7E6767B2C853941CCBA8)  
chainConfig: [0xC99Ab7737bC1d37A3B4722E82c11fE8d563991eD](https://sepolia.etherscan.io/address/0xC99Ab7737bC1d37A3B4722E82c11fE8d563991eD)  
skinnyIMTPoseidon2WriteStorage: [0x00000066C760D24272a9E8A424EF7233A0F0da83](https://sepolia.etherscan.io/address/0x00000066C760D24272a9E8A424EF7233A0F0da83)