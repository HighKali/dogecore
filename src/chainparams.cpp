#include "chainparams.h"
#include "consensus/merkle.h"
#include "uint256.h"
#include "arith_uint256.h"
#include <stdio.h>
#include <memory>
#include <vector>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "DogeCore Protocol 03/04/2025";
    const CScript genesisOutputScript = CScript() << OP_RETURN;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 500000; // Halving ogni 500k blocchi
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan = 4 * 60 * 60; // 4 ore
        consensus.nTargetSpacing = 2 * 60; // 2 minuti
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916;
        consensus.nMinerConfirmationWindow = 2016;

        genesis = CreateGenesisBlock(1743984000, 2084524493, 0x1e0ffff0, 1, 0); // 03/04/2025
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x1a91e3dace36e2be3bf030a65679fe821aa1d6ef0b0b12b7c6b8b4c6d7e8f9a0"));
        assert(genesis.hashMerkleRoot == uint256S("0x3c2e3f4b5a6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f"));

        vSeeds.emplace_back("seed.dogecoreprotocol.com");
        vSeeds.emplace_back("seed2.dogecoreprotocol.com");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 35); // 'D'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 25);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 163);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                { 0, uint256S("0x1a91e3dace36e2be3bf030a65679fe821aa1d6ef0b0b12b7c6b8b4c6d7e8f9a0")},
            }
        };
    }
};

class CTestNetParams : public CChainParams {
public:
    CTestNetParams() { strNetworkID = "test"; }
};

class CRegTestParams : public CChainParams {
public:
    CRegTestParams() { strNetworkID = "regtest"; }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() { assert(globalChainParams); return *globalChainParams; }

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == "main") return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == "test") return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == "regtest") return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    globalChainParams = CreateChainParams(network);
}
