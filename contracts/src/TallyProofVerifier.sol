// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title TallyProofVerifier
/// @notice Verifies ZK-SNARK proofs that tally was computed correctly
/// @dev Uses Groth16 pairing-based verification
contract TallyProofVerifier {
    // Verification key (generated during trusted setup)
    struct VerifyingKey {
        uint256[2] alpha1;
        uint256[2][2] beta2;
        uint256[2][2] gamma2;
        uint256[2][2] delta2;
        uint256[2][] ic; // Intermediate curve points
    }
    
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }
    
    struct PublicInputs {
        bytes32 encryptedVotesCommitment;  // Merkle root of all encrypted votes
        uint256 forVotes;                   // Claimed tally: votes FOR
        uint256 againstVotes;               // Claimed tally: votes AGAINST
        uint256 abstainVotes;               // Claimed tally: votes ABSTAIN
        bytes32 sessionPublicKeyHash;       // Hash of TEE public key used
    }
    
    VerifyingKey internal vk;
    
    event ProofVerified(bytes32 indexed votesCommitment, uint256 totalVotes);
    
    error InvalidProof();
    error InvalidPublicInputs();
    
    constructor() {
        // Initialize verification key from trusted setup
        // This would be generated using snarkjs or similar
        // For now, placeholder structure
        vk.ic = new uint256[2][](6); // 5 public inputs + 1
    }
    
    /// @notice Verify that tally matches encrypted votes
    /// @dev Proves: "I decrypted all votes in the commitment and tallied them correctly"
    /// @param proof ZK-SNARK Groth16 proof
    /// @param inputs Public inputs (commitment, tallies)
    /// @return bool True if proof is valid
    function verifyTally(
        Proof calldata proof,
        PublicInputs calldata inputs
    ) external returns (bool) {
        // Validate inputs are reasonable
        if (inputs.forVotes + inputs.againstVotes + inputs.abstainVotes > type(uint128).max) {
            revert InvalidPublicInputs();
        }
        
        // Convert public inputs to field elements
        uint256[] memory publicInputs = new uint256[](5);
        publicInputs[0] = uint256(inputs.encryptedVotesCommitment);
        publicInputs[1] = inputs.forVotes;
        publicInputs[2] = inputs.againstVotes;
        publicInputs[3] = inputs.abstainVotes;
        publicInputs[4] = uint256(inputs.sessionPublicKeyHash);
        
        // Verify the proof
        bool isValid = verifyGroth16Proof(proof, publicInputs);
        
        if (!isValid) revert InvalidProof();
        
        emit ProofVerified(
            inputs.encryptedVotesCommitment,
            inputs.forVotes + inputs.againstVotes + inputs.abstainVotes
        );
        
        return true;
    }
    
    /// @dev Verify Groth16 proof using pairing checks
    /// @dev Implements: e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
    function verifyGroth16Proof(
        Proof calldata proof,
        uint256[] memory publicInputs
    ) internal view returns (bool) {
        // Check proof is on curve
        if (!isOnCurve(proof.a) || !isOnCurve(proof.c)) return false;
        if (!isOnCurveG2(proof.b)) return false;
        
        // Compute vk_x = IC[0] + sum(publicInputs[i] * IC[i+1])
        uint256[2] memory vk_x = vk.ic[0];
        
        for (uint i = 0; i < publicInputs.length; i++) {
            uint256[2] memory scaled = scalarMul(vk.ic[i + 1], publicInputs[i]);
            vk_x = pointAdd(vk_x, scaled);
        }
        
        // Verify pairing equation using precompile
        // e(A, B) = e(alpha1, beta2) * e(vk_x, gamma2) * e(C, delta2)
        return verifyPairing(proof, vk_x);
    }
    
    /// @dev Verify pairing equation using bn256 precompile
    function verifyPairing(
        Proof calldata proof,
        uint256[2] memory vk_x
    ) internal view returns (bool) {
        // Prepare pairing input
        uint256[24] memory input;
        
        // -A
        input[0] = proof.a[0];
        input[1] = proof.a[1];
        
        // B
        input[2] = proof.b[0][0];
        input[3] = proof.b[0][1];
        input[4] = proof.b[1][0];
        input[5] = proof.b[1][1];
        
        // alpha1
        input[6] = vk.alpha1[0];
        input[7] = vk.alpha1[1];
        
        // beta2
        input[8] = vk.beta2[0][0];
        input[9] = vk.beta2[0][1];
        input[10] = vk.beta2[1][0];
        input[11] = vk.beta2[1][1];
        
        // vk_x
        input[12] = vk_x[0];
        input[13] = vk_x[1];
        
        // gamma2
        input[14] = vk.gamma2[0][0];
        input[15] = vk.gamma2[0][1];
        input[16] = vk.gamma2[1][0];
        input[17] = vk.gamma2[1][1];
        
        // C
        input[18] = proof.c[0];
        input[19] = proof.c[1];
        
        // delta2
        input[20] = vk.delta2[0][0];
        input[21] = vk.delta2[0][1];
        input[22] = vk.delta2[1][0];
        input[23] = vk.delta2[1][1];
        
        // Call bn256 pairing precompile (address 0x08)
        uint256[1] memory out;
        bool success;
        
        assembly {
            success := staticcall(gas(), 0x08, input, 768, out, 32)
        }
        
        return success && out[0] == 1;
    }
    
    /// @dev Check if point is on BN256 curve
    function isOnCurve(uint256[2] memory point) internal pure returns (bool) {
        uint256 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        
        if (point[0] >= p || point[1] >= p) return false;
        
        // Check y^2 = x^3 + 3
        uint256 lhs = mulmod(point[1], point[1], p);
        uint256 rhs = addmod(mulmod(mulmod(point[0], point[0], p), point[0], p), 3, p);
        
        return lhs == rhs;
    }
    
    /// @dev Check if point is on BN256 G2 curve
    function isOnCurveG2(uint256[2][2] memory point) internal pure returns (bool) {
        // Simplified check for G2 point validity
        uint256 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        return point[0][0] < p && point[0][1] < p && point[1][0] < p && point[1][1] < p;
    }
    
    /// @dev Scalar multiplication on BN256
    function scalarMul(uint256[2] memory point, uint256 scalar) internal view returns (uint256[2] memory) {
        uint256[3] memory input;
        input[0] = point[0];
        input[1] = point[1];
        input[2] = scalar;
        
        uint256[2] memory result;
        bool success;
        
        assembly {
            success := staticcall(gas(), 0x07, input, 96, result, 64)
        }
        
        require(success, "Scalar mul failed");
        return result;
    }
    
    /// @dev Point addition on BN256
    function pointAdd(uint256[2] memory p1, uint256[2] memory p2) internal view returns (uint256[2] memory) {
        uint256[4] memory input;
        input[0] = p1[0];
        input[1] = p1[1];
        input[2] = p2[0];
        input[3] = p2[1];
        
        uint256[2] memory result;
        bool success;
        
        assembly {
            success := staticcall(gas(), 0x06, input, 128, result, 64)
        }
        
        require(success, "Point add failed");
        return result;
    }
}

