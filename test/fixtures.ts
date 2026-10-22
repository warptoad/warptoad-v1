/**
 * Shared deploy steps for the hardhat tests. Not a test file, node:test just finds nothing in here.
 *
 * `deployInfra` once per network: the CREATE2 factory, the SkinnyIMT library at its canonical address and the
 * Poseidon2 Yul contract etched at the address poseidon2-evm hardcodes. `deployWarptoad` as often as a test wants
 * a fresh tree: ChainConfig for the local chain, verifier, Warptoad and a WrapperFactory
 */
import type { network } from "hardhat";
import { parseEther, type Address, type Hex } from "viem";
import { deployCreate2, type Create2Artifact, deployCreate2Factory } from "@warptoad/skinny-fat-imt-js/create2";
import { chainConfigArgs, NAME_PREFIX, SYMBOL_PREFIX } from "../src/config.js";
import { CIRCUIT_SIZE } from "../src/constants.js";
import type { WarptoadContract, WrapperERC20Contract, WrapperFactoryContract } from "../src/types.js";
import skinnyIMTArtifact from "@warptoad/skinny-fat-imt-js/create2/evm-artifacts/SkinnyIMTPoseidon2WriteStorage" with { type: "json" };
import IMTSalts from "@warptoad/skinny-fat-imt-js/create2/evm-artifacts/create2-salts.json" with { type: "json" };
import poseidon2YulArtifact from "poseidon2-evm/out/Poseidon2Yul.sol/Poseidon2Yul_BN254.json" with { type: "json" };

export type Connection = Awaited<ReturnType<typeof network.create>>;
export type Viem = Connection["viem"];
export type PublicClient = Awaited<ReturnType<Viem["getPublicClient"]>>;
export type WalletClient = Awaited<ReturnType<Viem["getWalletClients"]>>[number];

/**
 * The address `poseidon2-evm`'s `Poseidon2` library hardcodes for its Yul contract. Same on every chain zemse has
 * deployed it to. It publishes no CREATE2 salt, so unlike the IMT library it cannot be redeployed to that address
 * locally: etching the shipped runtime bytecode is the only way to reach it from a fresh node.
 * @TODO open an issue at github.com/zemse/poseidon2-evm asking for the deployment salt to be published
 */
export const POSEIDON2_YUL = "0xB2542195Ad96AcfBC962C48A97D7640A9F5386D2" as const;
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

export type Infra = { skinnyIMT: Address };

export async function deployInfra(viem: Viem, publicClient: PublicClient, deployer: WalletClient): Promise<Infra> {
    await deployCreate2Factory(publicClient, deployer, deployer.account);
    const skinnyIMT = await deployCreate2({
        artifact: skinnyIMTArtifact as Create2Artifact,
        salt: IMTSalts.SkinnyIMTPoseidon2WriteStorage[0] as Hex,
        walletClient: deployer,
        publicClient: publicClient,
    });
    const testClient = await viem.getTestClient();
    await testClient.setCode({
        address: POSEIDON2_YUL,
        bytecode: poseidon2YulArtifact.deployedBytecode.object as Hex,
    });
    return { skinnyIMT: skinnyIMT.address };
}

export type Deployment = Awaited<ReturnType<typeof deployWarptoad>>;

/** everything a test needs, on the local chain config (31337 -> gigaIndex 0) */
export async function deployWarptoad(viem: Viem, infra: Infra) {
    const [chainIds, infos] = chainConfigArgs(["local"]);
    const chainConfig = await viem.deployContract("ChainConfig", [chainIds, infos]);
    // generated from the circuit by `pnpm noir`
    const verifier = await viem.deployContract("WarptoadVerifier");
    const warptoad: WarptoadContract = await viem.deployContract(
        "Warptoad",
        [verifier.address, BigInt(CIRCUIT_SIZE), chainConfig.address],
        { libraries: { SkinnyIMTPoseidon2WriteStorage: infra.skinnyIMT } },
    );
    const factory: WrapperFactoryContract = await viem.deployContract("WrapperFactory", [
        SYMBOL_PREFIX,
        NAME_PREFIX,
        warptoad.address,
        chainConfig.address,
    ]);
    const gigaIndex = BigInt(await warptoad.read.gigaIndex());
    return { chainConfig, verifier, warptoad, factory, gigaIndex };
}

/**
 * on a live chain alice and bob are their own accounts (see hardhat.config.ts) and need gas. The deployer tops
 * `to` up to `topUp` when it holds less than `min`. No-op for the deployer itself
 */
export async function fundIfLow(
    publicClient: PublicClient,
    deployer: WalletClient,
    to: Address,
    { min = parseEther("0.02"), topUp = parseEther("0.05") } = {},
): Promise<void> {
    if (to.toLowerCase() === deployer.account.address.toLowerCase()) return;
    if ((await publicClient.getBalance({ address: to })) >= min) return;
    const hash = await deployer.sendTransaction({ to, value: topUp });
    await publicClient.waitForTransactionReceipt({ hash });
}

/** wrap, then look the wrapper up in the factory's `wrappers` mapping under this chain's giga index */
export async function wrap(
    viem: Viem,
    { factory, gigaIndex }: { factory: WrapperFactoryContract; gigaIndex: bigint },
    underlying: Address,
    amount: bigint,
    to: Address,
    from: Address,
): Promise<WrapperERC20Contract> {
    const hash = await factory.write.wrap([underlying, amount, to], { account: from });
    // instant on hardhat, needed on a live chain before the next step reads balances
    await (await viem.getPublicClient()).waitForTransactionReceipt({ hash });
    return viem.getContractAt("WrapperERC20", await factory.read.wrappers([underlying, gigaIndex]));
}
