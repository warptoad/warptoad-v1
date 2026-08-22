export const WARPTOAD_CONTRACT_NAME = "Warptoad"
export const SYMBOL_PREFIX = "WRPTD"
export const NAME_PREFIX = "Warptoad"

/**
 * Chain labels baked into wrapped-token `symbol()` / `name()`.
 *
 * Deliberately hardcoded rather than resolved from viem/chains or the
 * chainid.network registry at deploy time: these strings become permanent
 * on-chain metadata, so a dependency bump must never be able to change what
 * a future deployment names its tokens.
 *
 * `symbol` is not EIP-3770 `shortName` — it is uppercased and shortened for
 * legibility in wallets (arb1 -> ARB, oeth -> OP, scr -> SCR). Chain ids are
 * the authority; the labels are cosmetic.
 */
export const CHAIN_INFO = {
  // --- mainnets ---
  1:        { symbol: "ETH",  name: "Ethereum"          },
  10:       { symbol: "OP",   name: "Optimism"          },
  137:      { symbol: "POL",  name: "Polygon"           },
  324:      { symbol: "ZK",   name: "ZKsync"            },
  2741:     { symbol: "ABS",  name: "Abstract"          },
  8453:     { symbol: "BASE", name: "Base"              },
  42161:    { symbol: "ARB",  name: "Arbitrum"          },
  57073:    { symbol: "INK",  name: "Ink"               },
  534352:   { symbol: "SCR",  name: "Scroll"            },
  1027303:  { symbol: "FCT",  name: "Facet"             },

  // --- testnets ---
  // 31337 is the de-facto Hardhat/Anvil local id, not a registered public
  // chain (chainid.network maps it to GoChain Testnet). Local only.
  300:      { symbol: "ZK",   name: "ZKsync Sepolia"            },
  11124:    { symbol: "ABS",  name: "Abstract Sepolia"          },
  31337:    { symbol: "ETH",  name: "Ethereum Local Testnet"    },
  80002:    { symbol: "POL",  name: "Polygon Amoy"              },
  84532:    { symbol: "BASE", name: "Base Sepolia"              },
  421614:   { symbol: "ARB",  name: "Arbitrum Sepolia"          },
  534351:   { symbol: "SCR",  name: "Scroll Sepolia"            },
  763373:   { symbol: "INK",  name: "Ink Sepolia"               },
  11155111: { symbol: "ETH",  name: "Ethereum Sepolia"          },
  11155420: { symbol: "OP",   name: "Optimism Sepolia"          },
  16436858: { symbol: "FCT",  name: "Facet Sepolia"             },
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
