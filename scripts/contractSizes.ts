/**
 * Deployed and init code size of every compiled contract, read from the hardhat artifacts. Shared by
 * scripts/size.ts and scripts/bench.ts.
 *
 * `bytes` is `deployedBytecode`, what EIP-170 caps. `initBytes` is `bytecode`, the initcode with the constructor,
 * which EIP-3860 caps separately at 49152
 */
import { globSync, readFileSync } from "node:fs"

export const EIP_170_LIMIT = 24576
export const EIP_3860_LIMIT = 49152

export interface ContractSize {
  name: string
  sourceName: string
  bytes: number
  initBytes: number
  buildInfoId: string
}

interface Artifact {
  contractName: string
  sourceName: string
  bytecode: string
  deployedBytecode: string
  buildInfoId: string
}

/** biggest first. Interfaces and abstract contracts have no bytecode and are left out */
export function contractSizes(): ContractSize[] {
  return globSync("artifacts/contracts/**/*.json")
    .filter((f) => !f.endsWith(".dbg.json"))
    .map((f) => JSON.parse(readFileSync(f, "utf8")) as Artifact)
    .filter((a) => a.contractName && a.deployedBytecode?.length > 2)
    .map((a) => ({
      name: a.contractName,
      sourceName: a.sourceName,
      bytes: (a.deployedBytecode.length - 2) / 2,
      initBytes: (a.bytecode.length - 2) / 2,
      buildInfoId: a.buildInfoId,
    }))
    .sort((a, b) => b.bytes - a.bytes)
}
