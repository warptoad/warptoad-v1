/**
 * Assets: how a wrapped token becomes an `assetId` and back.
 *
 *   wrapperAssetHash = keccak31(abi.encode(wrapper, underlying))            WrapperFactory._hashAssetArgs
 *   wrapperId        = keccak31(abi.encode(wrapperFactory, wrapperAssetHash)) Warptoad.shield
 *   assetId          = Poseidon2(firstGigaIndex, lastGigaIndex, wrapperId)    hash_asset_id, the range is the factory's
 *
 * A note only carries `assetId`. Spending needs the preimage, so `resolveAsset` walks it back with eth_calls:
 * Warptoad.assetSources -> factory.gigaIndexRange + factory.wrapperOf -> the wrapper's own metadata.
 * See ENCRYPTED_BLOB_SPEC_DRAFT.md for which chain to ask
 */
import {
    concatHex,
    encodeAbiParameters,
    getContractAddress,
    parseAbi,
    type Address,
    type Hex,
    type PublicClient,
} from "viem";
import { NAME_PREFIX, SYMBOL_PREFIX } from "./config.js";
import { hashAssetId, keccak31Byte } from "./hashing.js";
import type { Asset, WarptoadContract } from "./types.js";

// ---------- hashes ----------

/** mirror of `WrapperFactory._hashAssetArgs` */
export function hashWrapperAssetHash({ wrapper, underlying }: { wrapper: Address; underlying: Address }): bigint {
    return keccak31Byte(encodeAbiParameters([{ type: "address" }, { type: "address" }], [wrapper, underlying]));
}

/** mirror of the `_wrapperId` in `Warptoad.shield` and `Warptoad.registerAsset` */
export function hashWrapperId({ wrapperFactory, wrapperAssetHash }: { wrapperFactory: Address; wrapperAssetHash: bigint }): bigint {
    return keccak31Byte(encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [wrapperFactory, wrapperAssetHash]));
}

/** the asset of `wrapper` as issued by `wrapperFactory`, whose trusted range is [firstGigaIndex, lastGigaIndex] */
export function assetOf({
    wrapperFactory,
    wrapper,
    underlying,
    firstGigaIndex,
    lastGigaIndex,
}: {
    wrapperFactory: Address;
    wrapper: Address;
    underlying: Address;
    firstGigaIndex: bigint;
    lastGigaIndex: bigint;
}): Asset {
    const wrapperAssetHash = hashWrapperAssetHash({ wrapper, underlying });
    return { firstGigaIndex, lastGigaIndex, wrapperId: hashWrapperId({ wrapperFactory, wrapperAssetHash }) };
}

// ---------- wrapper args ----------

/** everything `WrapperFactory._deploy` needs, which is also everything the wrapper's CREATE2 address commits to */
export type WrapperDeployInfo = {
    underlying: Address;
    /** gigaIndex of the chain the underlying was wrapped on, the only chain it can be unwrapped on */
    originGigaIndex: bigint;
    /** already formatted, see formatWrapperName */
    name: string;
    symbol: string;
    decimals: number;
};

/** `wrapperArgs` for shield, and for unshield on a chain where the wrapper already exists. The factory only decodes these two */
export function encodeWrapperArgs({ wrapper, underlying }: { wrapper: Address; underlying: Address }): Hex {
    return encodeAbiParameters([{ type: "address" }, { type: "address" }], [wrapper, underlying]);
}

/**
 * `wrapperArgs` for unshield on a chain where the wrapper does not exist yet: the factory deploys it from these and
 * checks the address matches `wrapper`. Works everywhere the short form works too
 */
export function encodeWrapperDeployArgs(wrapper: Address, info: WrapperDeployInfo): Hex {
    return encodeAbiParameters(
        [{ type: "address" }, { type: "address" }, { type: "string" }, { type: "string" }, { type: "uint8" }, { type: "uint64" }],
        [wrapper, info.underlying, info.name, info.symbol, info.decimals, info.originGigaIndex],
    );
}

/** mirror of `WrapperFactory._formatTokenSymbol`: wtUSDC@eth */
export function formatWrapperSymbol(baseSymbol: string, chainSymbol: string): string {
    return `${SYMBOL_PREFIX}${baseSymbol}@${chainSymbol}`;
}

/** mirror of `WrapperFactory._formatTokenName`: Wrapped Warptoad USD Coin Ethereum */
export function formatWrapperName(baseName: string, chainName: string): string {
    return `Wrapped ${NAME_PREFIX} ${baseName} ${chainName}`;
}

/**
 * mirror of `WrapperFactory._computeWrapperAddress`: CREATE2 from the factory, salt 0, init code = WrapperERC20
 * creation code + constructor args. `creationCode` is the `bytecode` of the WrapperERC20 artifact
 */
export function computeWrapperAddress({
    wrapperFactory,
    creationCode,
    ...info
}: WrapperDeployInfo & { wrapperFactory: Address; creationCode: Hex }): Address {
    const constructorArgs = encodeAbiParameters(
        [{ type: "address" }, { type: "uint64" }, { type: "string" }, { type: "string" }, { type: "uint8" }],
        [info.underlying, info.originGigaIndex, info.name, info.symbol, info.decimals],
    );
    return getContractAddress({
        opcode: "CREATE2",
        from: wrapperFactory,
        salt: `0x${"00".repeat(32)}`,
        bytecode: concatHex([creationCode, constructorArgs]),
    });
}

// ---------- resolving an assetId back to its preimage ----------

/** the views `resolveAsset` needs, so it doesn't depend on hardhat artifacts */
export const WRAPPER_FACTORY_VIEW_ABI = parseAbi([
    "function gigaIndexRange() view returns (uint256, uint256)",
    "function wrapperOf(uint256 wrapperAssetHash) view returns (address)",
]);
export const WRAPPER_ERC20_VIEW_ABI = parseAbi([
    "function underlying() view returns (address)",
    "function originGigaIndex() view returns (uint64)",
    "function name() view returns (string)",
    "function symbol() view returns (string)",
    "function decimals() view returns (uint8)",
]);

export type ResolvedAsset = {
    asset: Asset;
    wrapperFactory: Address;
    wrapperAssetHash: bigint;
    wrapper: Address;
    /** enough to build `encodeWrapperDeployArgs` for an unshield on any chain */
    deployInfo: WrapperDeployInfo;
};

/**
 * eth_calls only: `assetId` -> what to put in a spend and in an unshield. Throws if `warptoad` never saw the asset
 * (ask the chain the blob names, see ENCRYPTED_BLOB_SPEC_DRAFT.md) or if the contracts disagree with the hash
 */
export async function resolveAsset(warptoad: WarptoadContract, publicClient: PublicClient, assetId: bigint): Promise<ResolvedAsset> {
    const [wrapperFactory, wrapperAssetHash] = await warptoad.read.assetSources([assetId]);
    if (BigInt(wrapperFactory) === 0n) throw new Error(`assetId ${assetId} is not registered on this chain's Warptoad`);
    const factory = { address: wrapperFactory, abi: WRAPPER_FACTORY_VIEW_ABI } as const;
    const [[firstGigaIndex, lastGigaIndex], wrapper] = await Promise.all([
        publicClient.readContract({ ...factory, functionName: "gigaIndexRange" }),
        publicClient.readContract({ ...factory, functionName: "wrapperOf", args: [wrapperAssetHash] }),
    ]);
    const asset: Asset = { firstGigaIndex, lastGigaIndex, wrapperId: hashWrapperId({ wrapperFactory, wrapperAssetHash }) };
    if (hashAssetId(asset) !== assetId) throw new Error(`Warptoad.assetSources[${assetId}] does not hash back to it`);
    if (BigInt(wrapper) === 0n) throw new Error(`factory ${wrapperFactory} has no wrapper for ${wrapperAssetHash}`);

    const token = { address: wrapper, abi: WRAPPER_ERC20_VIEW_ABI } as const;
    const [underlying, originGigaIndex, name, symbol, decimals] = await Promise.all([
        publicClient.readContract({ ...token, functionName: "underlying" }),
        publicClient.readContract({ ...token, functionName: "originGigaIndex" }),
        publicClient.readContract({ ...token, functionName: "name" }),
        publicClient.readContract({ ...token, functionName: "symbol" }),
        publicClient.readContract({ ...token, functionName: "decimals" }),
    ]);
    if (hashWrapperAssetHash({ wrapper, underlying }) !== wrapperAssetHash) {
        throw new Error(`wrapper ${wrapper} does not hash to ${wrapperAssetHash} with its underlying ${underlying}`);
    }
    return { asset, wrapperFactory, wrapperAssetHash, wrapper, deployInfo: { underlying, originGigaIndex, name, symbol, decimals } };
}
