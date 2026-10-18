import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { NAME_PREFIX, SYMBOL_PREFIX, chainConfigArgs } from "../../src/config.js";
import { CIRCUIT_SIZE } from "../../src/constants.js";
import skinnyIMTArtifact from "@warptoad/skinny-fat-imt-js/create2/evm-artifacts/SkinnyIMTPoseidon2WriteStorage" with { type: "json" };
import IMTSalts from "@warptoad/skinny-fat-imt-js/create2/evm-artifacts/create2-salts.json" with { type: "json" };

/**
 * Deploys ChainConfig, WarptoadVerifier, Warptoad and WrapperFactory, linked against an already deployed
 * SkinnyIMTPoseidon2WriteStorage.
 *
 * Nothing chain specific is passed in here on purpose. ChainConfig gets the full table (mainnet and sepolia) and
 * Warptoad and WrapperFactory read their own gigaIndex, chainSymbol and chainName from it by `block.chainid` in
 * their constructors. A deploy on a chain missing from the table reverts, see contracts/ChainConfig.sol.
 *
 * The IMT library is a CREATE2 deployment, so it has the same address on every chain (see create2-salts.json).
 * The library is not compiled into this repo's artifacts, so its abi comes from the frozen create2 artifact.
 */
export default buildModule("Warptoad", (m) => {
    const skinnyIMTAddress = m.getParameter<string>("skinnyIMT", IMTSalts.SkinnyIMTPoseidon2WriteStorage[1]);

    const skinnyIMT = m.contractAt(
        "SkinnyIMTPoseidon2WriteStorage",
        {
            _format: "hh3-artifact-1",
            contractName: skinnyIMTArtifact.contractName,
            sourceName: skinnyIMTArtifact.sourceName,
            abi: skinnyIMTArtifact.abi,
            bytecode: skinnyIMTArtifact.initCode,
            deployedBytecode: skinnyIMTArtifact.deployedBytecode,
            linkReferences: {},
            deployedLinkReferences: {},
        },
        skinnyIMTAddress,
    );

    const [chainIds, infos] = chainConfigArgs();
    const chainConfig = m.contract("ChainConfig", [chainIds, infos]);

    const verifier = m.contract("WarptoadVerifier");

    const warptoad = m.contract(
        "Warptoad",
        [verifier, BigInt(CIRCUIT_SIZE), chainConfig],
        { libraries: { SkinnyIMTPoseidon2WriteStorage: skinnyIMT } },
    );

    const wrapperFactory = m.contract("WrapperFactory", [SYMBOL_PREFIX, NAME_PREFIX, warptoad, chainConfig]);

    return { chainConfig, warptoad, verifier, wrapperFactory, skinnyIMT };
});
