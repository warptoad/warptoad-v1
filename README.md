# warptoad-v1

Solidity contracts (Hardhat 3 + viem) and Noir circuits.

## Contracts

```sh
pnpm install
pnpm compile   # hardhat compile
pnpm test      # hardhat test
pnpm size      # contract size report
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
