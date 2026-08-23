/**
 * Reports deployed bytecode size for every compiled contract.
 *
 * EIP-170 caps runtime code at 24576 bytes; going over makes deployment fail
 * rather than revert, so this exits non-zero to catch it in CI.
 *
 * Measures `deployedBytecode`, not `bytecode` — the latter is initcode, which
 * includes the constructor and is governed by EIP-3860's separate 49152 limit.
 */
import { globSync, readFileSync } from "node:fs"

const EIP_170_LIMIT = 24576
const WARN_RATIO = 0.9

interface Artifact {
  contractName: string
  deployedBytecode: string
}

const color = process.stdout.isTTY
  ? (code: number, s: string) => `\x1b[${code}m${s}\x1b[0m`
  : (_code: number, s: string) => s

const sizes = globSync("artifacts/contracts/**/*.json")
  .filter((f) => !f.endsWith(".dbg.json"))
  .map((f) => JSON.parse(readFileSync(f, "utf8")) as Artifact)
  .filter((a) => a.contractName && a.deployedBytecode?.length > 2)
  .map((a) => ({ name: a.contractName, bytes: (a.deployedBytecode.length - 2) / 2 }))
  .sort((a, b) => b.bytes - a.bytes)

if (sizes.length === 0) {
  console.error("No artifacts found — run `pnpm compile` first.")
  process.exit(1)
}

console.log(`\n  bytes / ${EIP_170_LIMIT}   used  contract`)

for (const { name, bytes } of sizes) {
  const ratio = bytes / EIP_170_LIMIT
  const line =
    `${String(bytes).padStart(7)} / ${EIP_170_LIMIT}  ` +
    `${(ratio * 100).toFixed(1).padStart(5)}%  ${name}`
  console.log(ratio > 1 ? color(31, `${line}  OVER LIMIT`) : ratio >= WARN_RATIO ? color(33, line) : line)
}

const over = sizes.filter((s) => s.bytes > EIP_170_LIMIT)
if (over.length > 0) {
  console.error(`\n${over.length} contract(s) exceed the EIP-170 limit and cannot be deployed.\n`)
  process.exit(1)
}
console.log("")
