#include <sodium.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <fstream>

// CRITICAL SECURITY PRINCIPLE:
// The private key (sk) NEVER leaves this TEE enclave.
// It is generated here, used here for decryption, and destroyed here.
// Only the PUBLIC key is ever transmitted outside the enclave.

struct Vote {
    std::string proposalId;
    std::string choice; // "for", "against", "abstain"
    std::string weight;
    std::string nonce;
};

// Secure memory management: zero memory before free
template<typename T>
void secure_zero(std::vector<T>& data) {
    sodium_memzero(data.data(), data.size() * sizeof(T));
}

// Parse JSON vote payload (simplified - use proper JSON library in production)
Vote parseVotePayload(const std::string& json) {
    Vote vote;
    // Simplified parsing - in production use nlohmann/json or similar
    size_t propIdPos = json.find("\"proposalId\":\"");
    if (propIdPos != std::string::npos) {
        propIdPos += 14;
        size_t propIdEnd = json.find("\"", propIdPos);
        vote.proposalId = json.substr(propIdPos, propIdEnd - propIdPos);
    }
    
    size_t choicePos = json.find("\"choice\":\"");
    if (choicePos != std::string::npos) {
        choicePos += 10;
        size_t choiceEnd = json.find("\"", choicePos);
        vote.choice = json.substr(choicePos, choiceEnd - choicePos);
    }
    
    size_t weightPos = json.find("\"weight\":\"");
    if (weightPos != std::string::npos) {
        weightPos += 10;
        size_t weightEnd = json.find("\"", weightPos);
        vote.weight = json.substr(weightPos, weightEnd - weightPos);
    } else {
        vote.weight = "1000"; // Default weight
    }
    
    size_t noncePos = json.find("\"nonce\":\"");
    if (noncePos != std::string::npos) {
        noncePos += 9;
        size_t nonceEnd = json.find("\"", noncePos);
        vote.nonce = json.substr(noncePos, nonceEnd - noncePos);
    }
    
    return vote;
}

// Generate SGX attestation report
std::string generateSGXAttestation(const unsigned char* public_key, size_t pk_len) {
    // In a real SGX enclave, this would call:
    // - sgx_create_report() to create a report
    // - Include public_key hash in report_data field
    // - Get IAS to sign the quote via sgx_get_quote()
    
    // For now, output a placeholder structure that would be replaced
    // with actual SGX SDK calls in production
    
    std::stringstream attestation;
    attestation << "SGX_ATTESTATION_V1:";
    attestation << "MRENCLAVE="; // Would be filled by SGX
    attestation << "MRSIGNER=";  // Would be filled by SGX
    attestation << "REPORT_DATA=" << sodium_bin2hex(NULL, 0, public_key, 32); // First 32 bytes of PK
    attestation << ":IAS_SIGNATURE="; // Would be filled by IAS
    
    return attestation.str();
}

// Generate ZK proof of correct tallying
std::string generateTallyProof(
    const std::vector<std::string>& encryptedVotes,
    uint64_t forVotes,
    uint64_t againstVotes,
    uint64_t abstainVotes,
    const unsigned char* public_key
) {
    // In production, this would:
    // 1. Build a ZK circuit proving: "I decrypted all votes in encryptedVotes and got these tallies"
    // 2. Generate a Groth16/Plonk proof using libsnark or similar
    // 3. The proof would NOT reveal individual votes, only aggregate correctness
    
    // Compute commitment to encrypted votes
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    for (const auto& vote : encryptedVotes) {
        crypto_hash_sha256_update(&state, (const unsigned char*)vote.data(), vote.size());
    }
    unsigned char votesCommitment[crypto_hash_sha256_BYTES];
    crypto_hash_sha256_final(&state, votesCommitment);
    
    // Placeholder proof structure
    std::stringstream proof;
    proof << "ZK_PROOF_V1:";
    proof << "COMMITMENT=" << sodium_bin2hex(NULL, 0, votesCommitment, 32);
    proof << ":FOR=" << forVotes;
    proof << ":AGAINST=" << againstVotes;
    proof << ":ABSTAIN=" << abstainVotes;
    proof << ":PK_HASH=" << sodium_bin2hex(NULL, 0, public_key, 32);
    proof << ":PROOF="; // Would contain actual Groth16 proof bytes
    
    return proof.str();
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "ERROR: libsodium initialization failed" << std::endl;
        return 1;
    }
    
    std::cerr << "TEE: libsodium initialized" << std::endl;
    
    // STEP 1: Generate ephemeral keypair INSIDE the enclave
    // CRITICAL: The private key (sk) NEVER leaves this scope
    std::vector<unsigned char> pk(crypto_box_PUBLICKEYBYTES);
    std::vector<unsigned char> sk(crypto_box_SECRETKEYBYTES);
    
    crypto_box_keypair(pk.data(), sk.data());
    std::cerr << "TEE: Ephemeral keypair generated (private key confined to enclave)" << std::endl;
    
    // STEP 2: Output ONLY the public key for blockchain publication
    std::string pkHex = sodium_bin2hex(NULL, 0, pk.data(), pk.size());
    std::cout << "PUBLIC_KEY=" << pkHex << std::endl;
    std::cerr << "TEE: Public key published (safe to transmit)" << std::endl;
    
    // STEP 3: Generate attestation report proving this public key came from genuine SGX
    std::string attestation = generateSGXAttestation(pk.data(), pk.size());
    std::cout << "ATTESTATION=" << attestation << std::endl;
    std::cerr << "TEE: Attestation report generated" << std::endl;
    
    // STEP 4: Read encrypted votes from input
    // In production: read from iExec dataset or stdin
    std::cerr << "TEE: Waiting for encrypted votes (format: HEX_CIPHERTEXT per line, end with EOF)" << std::endl;
    
    std::vector<std::string> encryptedVotesHex;
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        encryptedVotesHex.push_back(line);
    }
    
    std::cerr << "TEE: Received " << encryptedVotesHex.size() << " encrypted votes" << std::endl;
    
    // STEP 5: Decrypt votes INSIDE the enclave using the private key
    uint64_t forVotes = 0;
    uint64_t againstVotes = 0;
    uint64_t abstainVotes = 0;
    uint64_t invalidVotes = 0;
    
    for (const auto& ciphertextHex : encryptedVotesHex) {
        // Convert hex to bytes
        std::vector<unsigned char> ciphertext(ciphertextHex.size() / 2);
        if (sodium_hex2bin(ciphertext.data(), ciphertext.size(), 
                          ciphertextHex.c_str(), ciphertextHex.size(),
                          nullptr, nullptr, nullptr) != 0) {
            std::cerr << "TEE: Invalid hex in ciphertext, skipping" << std::endl;
            invalidVotes++;
            continue;
        }
        
        // Decrypt using sealed box (private key stays in enclave!)
        std::vector<unsigned char> plaintext(ciphertext.size() - crypto_box_SEALBYTES);
        if (crypto_box_seal_open(plaintext.data(), ciphertext.data(), ciphertext.size(),
                                 pk.data(), sk.data()) != 0) {
            std::cerr << "TEE: Failed to decrypt vote, skipping" << std::endl;
            invalidVotes++;
            continue;
        }
        
        // Parse vote payload
        std::string json(plaintext.begin(), plaintext.end());
        Vote vote = parseVotePayload(json);
        
        // Tally the vote
        uint64_t weight = std::stoull(vote.weight);
        if (vote.choice == "for") {
            forVotes += weight;
        } else if (vote.choice == "against") {
            againstVotes += weight;
        } else if (vote.choice == "abstain") {
            abstainVotes += weight;
        } else {
            std::cerr << "TEE: Invalid vote choice: " << vote.choice << std::endl;
            invalidVotes++;
        }
        
        // Securely zero the plaintext
        secure_zero(plaintext);
    }
    
    std::cerr << "TEE: Tallying complete" << std::endl;
    std::cerr << "TEE:   For: " << forVotes << std::endl;
    std::cerr << "TEE:   Against: " << againstVotes << std::endl;
    std::cerr << "TEE:   Abstain: " << abstainVotes << std::endl;
    std::cerr << "TEE:   Invalid: " << invalidVotes << std::endl;
    
    // STEP 6: Generate ZK proof of correct tallying
    std::string zkProof = generateTallyProof(encryptedVotesHex, forVotes, againstVotes, abstainVotes, pk.data());
    
    // STEP 7: Output results with cryptographic proofs
    std::cout << "TALLY_FOR=" << forVotes << std::endl;
    std::cout << "TALLY_AGAINST=" << againstVotes << std::endl;
    std::cout << "TALLY_ABSTAIN=" << abstainVotes << std::endl;
    std::cout << "ZK_PROOF=" << zkProof << std::endl;
    
    // STEP 8: CRITICAL - Securely destroy the private key before exit
    std::cerr << "TEE: Securely destroying private key..." << std::endl;
    secure_zero(sk);
    secure_zero(pk); // Also zero public key from memory
    
    std::cerr << "TEE: Private key destroyed. Exiting securely." << std::endl;
    
    return 0;
}
