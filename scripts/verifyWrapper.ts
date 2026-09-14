/**
 * `hardhat verify-wrapper <address> --network <net>`: verifies a wrapper token Warptoad deployed on first wrap.
 * Reads the constructor args back from the wrapper and the Warptoad it points to, then runs the normal `verify` task.
 * Registered in hardhat.config.ts
 */
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";
import type { Address } from "viem";

const ERC20 = "contracts/WarptoadERC20.sol:WarptoadERC20";
const ERC1155 = "contracts/WarptoadERC1155.sol:WarptoadERC1155";

export default async function verifyWrapper({ wrapper }: { wrapper: string }, hre: HardhatRuntimeEnvironment) {
    const { viem } = await hre.network.create();
    // both wrappers share these getters
    const asErc20 = await viem.getContractAt("WarptoadERC20", wrapper as Address);
    const [warptoadAddress, underlying, name, symbol] = await Promise.all([
        asErc20.read.warptoad(),
        asErc20.read.underlying(),
        asErc20.read.name(),
        asErc20.read.symbol(),
    ]);
    const warptoad = await viem.getContractAt("Warptoad", warptoadAddress);

    let contract: string;
    let constructorArgs: string[];
    if ((await warptoad.read.erc20WrapperOf([underlying])).toLowerCase() === wrapper.toLowerCase()) {
        contract = ERC20;
        constructorArgs = [underlying, name, symbol, String(await asErc20.read.decimals())];
    } else if ((await warptoad.read.erc1155WrapperOf([underlying])).toLowerCase() === wrapper.toLowerCase()) {
        contract = ERC1155;
        constructorArgs = [underlying, name, symbol];
    } else {
        throw new Error(`${wrapper} is not a wrapper of Warptoad ${warptoadAddress}`);
    }
    console.log(`${contract.split(":")[1]} ${symbol} (${name}), underlying ${underlying}`);

    await hre.tasks.getTask("verify").run({ address: wrapper, constructorArgs, contract });
}
