/**
 * `hardhat verify-wrapper <address> --network <net>`: verifies a WrapperERC20 a WrapperFactory deployed.
 * Reads the constructor args back from the wrapper, checks the factory really issued it, then runs the normal
 * `verify` task. Registered in hardhat.config.ts
 */
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";
import type { Address } from "viem";
import { hashWrapperAssetHash } from "../src/assets.js";

const ERC20 = "contracts/WrapperERC20.sol:WrapperERC20";

export default async function verifyWrapper({ wrapper }: { wrapper: string }, hre: HardhatRuntimeEnvironment) {
    const { viem } = await hre.network.create();
    const token = await viem.getContractAt("WrapperERC20", wrapper as Address);
    const [factoryAddress, underlying, originGigaIndex, name, symbol, decimals] = await Promise.all([
        token.read.factory(),
        token.read.underlying(),
        token.read.originGigaIndex(),
        token.read.name(),
        token.read.symbol(),
        token.read.decimals(),
    ]);
    const factory = await viem.getContractAt("WrapperFactory", factoryAddress);
    const issued = await factory.read.wrapperOf([hashWrapperAssetHash({ wrapper: wrapper as Address, underlying })]);
    if (issued.toLowerCase() !== wrapper.toLowerCase()) {
        throw new Error(`${wrapper} is not a wrapper of WrapperFactory ${factoryAddress}`);
    }
    console.log(`WrapperERC20 ${symbol} (${name}), underlying ${underlying} wrapped on gigaIndex ${originGigaIndex}`);

    // same order as the WrapperERC20 constructor
    const constructorArgs = [underlying, String(originGigaIndex), name, symbol, String(decimals)];
    await hre.tasks.getTask("verify").run({ address: wrapper, constructorArgs, contract: ERC20 });
}
