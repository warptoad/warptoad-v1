import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import { network } from "hardhat";
import type { WarptoadContract } from "../src/types.js";
import { chainName, NAME_PREFIX, SYMBOL_PREFIX } from "../src/config.js";


describe("Counter", async function () {
  const { viem } = await network.create();
  const publicClient = await viem.getPublicClient();

  let warptoad:WarptoadContract;
  beforeEach(async () => {
    const chainId = await publicClient.getChainId()
    const chainNames = chainName(chainId)
    warptoad = await viem.deployContract("Warptoad",[SYMBOL_PREFIX, NAME_PREFIX, chainNames.symbol, chainNames.name]);
  });

  it("The sum of the Increment events should match the current value", async function () {
    warptoad
  });
});
