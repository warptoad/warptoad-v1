# Benchmarks

Written by `pnpm bench` (scripts/bench.ts), don't edit by hand. Build, circuit and gas are rewritten on every run, a
machine's section only when the bench runs on that machine.

## Build

solc 0.8.28+commit.7893614a, evm cancun, Warptoad optimizer on, 200 runs

| contract | runtime | of EIP-170 | initcode | of EIP-3860 | optimizer |
| --- | ---: | ---: | ---: | ---: | --- |
| WarptoadVerifier | 16,312 | 66.4% | 16,340 | 33.2% | on, 200 runs |
| WrapperFactory | 10,437 | 42.5% | 11,811 | 24.0% | on, 200 runs |
| Warptoad | 8,941 | 36.4% | 9,590 | 19.5% | on, 200 runs |
| WrapperERC20 | 2,367 | 9.6% | 3,228 | 6.6% | on, 200 runs |
| ChainConfig | 1,282 | 5.2% | 2,817 | 5.7% | on, 200 runs |
| TokenMetadata | 85 | 0.3% | 135 | 0.3% | on, 200 runs |

## Circuit

CIRCUIT_SIZE 4, MAX_TREE_DEPTH 40. nargo 1.0.0-beta.22, bb 5.0.0-nightly.20260523,
bb.js 5.0.0-nightly.20260525, noir_js 1.0.0-beta.22

| ACIR opcodes | gates | padded to | proof | public inputs | vk hash |
| ---: | ---: | ---: | ---: | ---: | --- |
| 18,400 | 55,956 | 2^16 | 8,768 bytes | 32 | `09a27078d50b41ef` |

## Gas

Hardhat chain, the setup the private txs below needed. Those are in the machine tables, next to their proofs

| tx | gas |
| --- | ---: |
| deploy Warptoad | 2,100,580 |
| deploy WarptoadVerifier | 3,579,379 |
| deploy WrapperFactory | 2,455,738 |
| shield (with an encrypted note) | 241,818 |
| wrap, first time (deploys the wrapper) | 862,793 |

## Machines

<!-- machine: AMD Ryzen 7 5800H with Radeon Graphics · 16 threads · 14.5 GiB RAM · 4.0 GiB swap -->
### AMD Ryzen 7 5800H with Radeon Graphics · 16 threads · 14.5 GiB RAM · 4.0 GiB swap

linux 7.0.0-38-generic, vk `09a27078d50b41ef`, Warptoad optimizer on, 200 runs. Median of 3 run(s),
peak memory is the max. Every slot carries a message. bb.js WASM startup (compile + CRS) takes another 0.65 s, not in its column.
verify gas is `WarptoadVerifier.verify` sent as a tx of its own, so with the 21k base and the proof's calldata

| tx | witness gen | witness (gz) | bb prove native | peak mem | bb.js prove wasm | peak mem | tx gas | verify gas |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| transfer | 0.44 s | 675 KiB (204 KiB) | 0.72 s | 110 MiB | 1.91 s | 660 MiB | 1,409,068 | 876,604 |
| unshield | 0.21 s | 675 KiB (205 KiB) | 0.68 s | 110 MiB | 1.93 s | 657 MiB | 1,387,471 | 877,579 |
| swaptoad fill | 0.23 s | 675 KiB (334 KiB) | 0.70 s | 112 MiB | 1.92 s | 657 MiB | 1,377,345 | 876,760 |
<!-- /machine -->
