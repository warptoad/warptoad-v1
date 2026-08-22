export const WARPTOAD_CONTRACT_NAME = "Warptoad"
export const SYMBOL_PREFIX = "wt"
export const NAME_PREFIX = "Warptoad"

/**
 * Chain labels baked into wrapped-token `symbol()` / `name()`.
 *
 * Deliberately hardcoded rather than resolved from viem/chains or the
 * chainid.network registry at deploy time: these strings become permanent
 * on-chain metadata, so a dependency bump must never be able to change what
 * a future deployment names its tokens.
 *
 * `symbol` is not EIP-3770 `shortName` — that standard would give `arb1`,
 * `oeth`, `matic`. These are shortened for legibility instead, and lowercased
 * so the chain tag never reads as another ticker: `wtUSDC@eth`, not
 * `wtUSDC@ETH`. Chain ids are the authority; the labels are cosmetic.
 */
export const CHAIN_INFO = {
  // --- mainnets ---
  1:        { symbol: "eth",  name: "Ethereum"          },
  10:       { symbol: "op",   name: "Optimism"          },
  137:      { symbol: "pol",  name: "Polygon"           },
  324:      { symbol: "zk",   name: "ZKsync"            },
  2741:     { symbol: "abs",  name: "Abstract"          },
  8453:     { symbol: "base", name: "Base"              },
  42161:    { symbol: "arb",  name: "Arbitrum"          },
  57073:    { symbol: "ink",  name: "Ink"               },
  534352:   { symbol: "scr",  name: "Scroll"            },
  1027303:  { symbol: "fct",  name: "Facet"             },

  // --- testnets ---
  // 31337 is the de-facto Hardhat/Anvil local id, not a registered public
  // chain (chainid.network maps it to GoChain Testnet). Local only.
  300:      { symbol: "zk",   name: "ZKsync Sepolia"            },
  11124:    { symbol: "abs",  name: "Abstract Sepolia"          },
  31337:    { symbol: "eth",  name: "Ethereum Local Testnet"    },
  80002:    { symbol: "pol",  name: "Polygon Amoy"              },
  84532:    { symbol: "base", name: "Base Sepolia"              },
  421614:   { symbol: "arb",  name: "Arbitrum Sepolia"          },
  534351:   { symbol: "scr",  name: "Scroll Sepolia"            },
  763373:   { symbol: "ink",  name: "Ink Sepolia"               },
  11155111: { symbol: "eth",  name: "Ethereum Sepolia"          },
  11155420: { symbol: "op",   name: "Optimism Sepolia"          },
  16436858: { symbol: "fct",  name: "Facet Sepolia"             },
} as const satisfies Record<number, ChainInfo>

export type ChainInfo = { symbol: string; name: string }
export type SupportedChainId = keyof typeof CHAIN_INFO

export function isSupportedChainId(chainId: number): chainId is SupportedChainId {
  return chainId in CHAIN_INFO
}

/**
 * Throws rather than falling back: a missing label would silently deploy a
 * mislabeled token, and token metadata cannot be corrected after the fact.
 */
export function chainName(chainId: number): ChainInfo {
  if (!isSupportedChainId(chainId)) {
    throw new Error(`Warptoad: unsupported chainId ${chainId}`)
  }
  return CHAIN_INFO[chainId]
}
