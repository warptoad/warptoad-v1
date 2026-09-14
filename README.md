# warptoad-v1

Solidity contracts (Hardhat 3 + viem) and Noir circuits.

## Contracts

```sh
pnpm install
pnpm compile   # hardhat compile
pnpm test      # hardhat test
pnpm size      # contract size report
```

### Gas

`pnpm hardhat test test/ClaudeLilMessaging.test.ts --gas-stats`, CIRCUIT_SIZE 4:

| | gas |
| --- | --- |
| `WarptoadVerifier.verify` on its own (8.7 KB proof, 30 public inputs) | ~875k, ~150k of that is calldata |
| `verifyShieldedTx` (1 spend, 1 unshield, 3 tree inserts) | ~1.37M |
| `shieldErc20` | ~211k |
| `wrapERC20` first time (deploys the wrapper) | ~756k |
| deploy `Warptoad` / `WarptoadVerifier` | 5.5M / 3.6M |

### Deploy + verify on Sepolia

Secrets go in the hardhat keystore once (plain env vars with the same names also work):

```sh
npx hardhat keystore set SEPOLIA_RPC_URL
npx hardhat keystore set SEPOLIA_PRIVATE_KEY
npx hardhat keystore set ETHERSCAN_API_KEY
```

deploy

```sh
pnpm deploy:sepolia   # ignition deploy + etherscan verify
```

Deploys `WarptoadVerifier` and `Warptoad` via `ignition/modules/Warptoad.ts`, linked to the
already deployed `SkinnyIMTPoseidon2WriteStorage`. Addresses land in
`ignition/deployments/chain-11155111/deployed_addresses.json`. Rerunning resumes, `--reset` starts over.

Chain labels come from `ignition/parameters/sepolia.json` and become permanent token metadata
(`wtUSDC@eth`), so for another chain copy them from `CHAIN_INFO` in `src/config.ts`.

Wrapper tokens are deployed by `Warptoad` itself on first wrap, so they might not be automatically
verified. In case you need one verified do:

```sh
pnpm verify:wrapper:sepolia 0xfc632092084235675bebe56263976397959a0ff7
```

Works for ERC-20 and ERC-1155 wrappers, the constructor args are read back from chain (`scripts/verifyWrapper.ts`).

To send real txs to the deployment, `test/ClaudeLilMessaging.test.ts` also runs against it. Use
`hardhat run`, not `hardhat test`: the test task never unlocks the password protected keystore
(it only reads the `--dev` one), `run` prompts for the password like deploy does.

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
cd circuits
nargo compile   # -> target/warptoad_v1.json
nargo test
nargo execute   # witness from Prover.toml (example EdDSA signature)

# -o is a directory; write_vk first, prove reads the vk it wrote
bb write_vk -b ./target/warptoad_v1.json -o ./target
bb prove -b ./target/warptoad_v1.json -w ./target/warptoad_v1.gz -o ./target
bb verify -k ./target/vk -p ./target/proof -i ./target/public_inputs
```

Add `--verifier_target evm` to `bb prove` for on-chain verification.

`eddsa` is pulled from `master` — the fix for modern Noir is unreleased
([eddsa#18](https://github.com/noir-lang/eddsa/issues/18)). nargo clones a
branch dep once and never re-fetches, so to pick up upstream changes:

```sh
rm -rf ~/nargo/github.com/noir-lang/eddsa/master
```

## aztec-nargo conflicts

Aztec ships its own nargo and puts it ahead of yours, so `nargo --version` shows
a version you never installed (`which -a nargo` shows who wins). We don't use
Aztec here — remove it, then reinstall Noir:

```sh
sudo rm -f /usr/local/bin/nargo /usr/local/bin/aztec
rm -rf ~/.aztec
```

Delete the `$HOME/.aztec/...` line from `~/.bashrc`, then redo
[Install Noir](#install-noir) and `source ~/.bashrc`.

Foundry is a separate install in `~/.foundry/bin`, so `forge`/`cast`/`anvil`
keep working. `aztec-up` reinstalls Aztec if you ever need it.

# deployments

warptoad: [0xC595711faa9D84D59D7904dbE8890c5b6662156F](https://sepolia.etherscan.io/address/0xC595711faa9D84D59D7904dbE8890c5b6662156F)  
verifier: [0x42768e1c3825dFF528A44CAC479c9900Dc344a3b](https://sepolia.etherscan.io/address/0x42768e1c3825dFF528A44CAC479c9900Dc344a3b)
