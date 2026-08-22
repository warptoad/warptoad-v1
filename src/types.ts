import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";
import type { WARPTOAD_CONTRACT_NAME } from "./config.js";
export type WarptoadContract = ContractReturnType<typeof WARPTOAD_CONTRACT_NAME>