#include "validation.h"
#include "arith_uint256.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/params.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <map>
#include <set>

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    if (nHeight == 0) {
        return 0; // Genesis block
    }

    CAmount nSubsidy = 100000 * COIN; // 100,000 DogeCore per blocco

    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    if (halvings >= 64) {
        return 1000 * COIN; // Minimo 1,000 DogeCore
    }

    nSubsidy >>= halvings;

    if (nSubsidy < 1000 * COIN) {
        nSubsidy = 1000 * COIN;
    }

    return nSubsidy;
}

bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot)
{
    if (block.fChecked) return true;
    if (block.GetHash() == consensusParams.hashGenesisBlock) return true;
    if (block.nVersion < 1) return state.DoS(100, false, REJECT_INVALID, "version-too-low");
    if (block.vtx.empty() || block.vtx.size() > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT) return state.DoS(100, false, REJECT_INVALID, "bad-blk-length");
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams)) return state.DoS(50, false, REJECT_INVALID, "high-hash");
    if (fCheckMerkleRoot && block.hashMerkleRoot != BlockMerkleRoot(block)) return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot");
    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& consensusParams)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(consensusParams.powLimit)) return false;
    if (UintToArith256(hash) > bnTarget) return false;
    return true;
}

bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev) { return true; }
bool CheckTransaction(const CTransaction& tx, CValidationState& state, bool fCheckDuplicateInputs) { return true; }
