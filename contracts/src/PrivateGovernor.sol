// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Governor} from "@openzeppelin/contracts/governance/Governor.sol";
import {IPrivateGovernor} from "./IPrivateGovernor.sol";
import {ITEEAttestor} from "./ITEEAttestor.sol";

/// @dev Minimal skeleton extending Governor to handle encrypted votes with TEE attestations.
abstract contract PrivateGovernor is Governor, IPrivateGovernor {
  error SessionKeyAlreadySet(uint256 proposalId);
  error SessionKeyNotSet(uint256 proposalId);
  error AttestationInvalid();
  error OnlyTEEFinalizer();
  error NullifierAlreadyUsed(bytes32 nullifier);
  error InvalidMerkleProof();
  error ZKProofVerificationFailed();

  ITEEAttestor public immutable teeAttestor;
  bytes32 public immutable expectedMrEnclave; // TEE measurement for the app
  bytes32 public immutable expectedMrSigner;  // TEE signer/IAS measurement

  // proposalId => TEE session public key (libsodium public key)
  mapping(uint256 => bytes) private _proposalPublicKey;

  // proposalId => has been finalized
  mapping(uint256 => bool) private _finalized;

  // address allowed to finalize tallies (e.g., relayer owned by TEE scheduler)
  address public immutable tallyFinalizer;
  
  // Merkle root of eligible voters (for anonymous voting)
  bytes32 public voterMerkleRoot;
  
  // Track used nullifiers to prevent double voting
  mapping(bytes32 => bool) public usedNullifiers;
  
  // ZK proof verifier for tally correctness
  address public immutable zkProofVerifier;

  constructor(
    string memory name_,
    ITEEAttestor _teeAttestor,
    bytes32 _expectedMrEnclave,
    bytes32 _expectedMrSigner,
    address _tallyFinalizer,
    address _zkProofVerifier,
    bytes32 _voterMerkleRoot
  ) Governor(name_) {
    teeAttestor = _teeAttestor;
    expectedMrEnclave = _expectedMrEnclave;
    expectedMrSigner = _expectedMrSigner;
    tallyFinalizer = _tallyFinalizer;
    zkProofVerifier = _zkProofVerifier;
    voterMerkleRoot = _voterMerkleRoot;
  }


  function sessionPublicKey(uint256 proposalId) public view returns (bytes memory) {
    return _proposalPublicKey[proposalId];
  }

  function publishSessionPublicKey(uint256 proposalId, bytes calldata teePublicKey, bytes calldata attestation) external override {
    if (_proposalPublicKey[proposalId].length != 0) revert SessionKeyAlreadySet(proposalId);
    // Verify TEE attestation for key publication
    bool ok = teeAttestor.verify(attestation, expectedMrEnclave, expectedMrSigner);
    if (!ok) revert AttestationInvalid();
    _proposalPublicKey[proposalId] = teePublicKey;
    emit SessionPublicKeyPublished(proposalId, teePublicKey);
  }

  function submitEncryptedVote(
    uint256 proposalId, 
    bytes calldata ciphertext,
    bytes32 nullifier,
    bytes32[] calldata merkleProof
  ) external override {
    if (_proposalPublicKey[proposalId].length == 0) revert SessionKeyNotSet(proposalId);
    
    // Check nullifier not already used (prevents double voting)
    if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
    
    // Verify voter is eligible via Merkle proof (anonymous)
    if (!verifyMerkleProof(merkleProof, voterMerkleRoot, keccak256(abi.encodePacked(_msgSender())))) {
      revert InvalidMerkleProof();
    }
    
    // Mark nullifier as used
    usedNullifiers[nullifier] = true;
    
    // Emit event with nullifier instead of address (breaks linkability)
    emit EncryptedVoteSubmitted(proposalId, nullifier, ciphertext);
  }

  function finalizeTally(
    uint256 proposalId,
    uint256 forVotes,
    uint256 againstVotes,
    uint256 abstainVotes,
    bytes calldata zkProof,
    bytes calldata attestation
  ) external override {
    if (_msgSender() != tallyFinalizer) revert OnlyTEEFinalizer();
    if (_finalized[proposalId]) revert("Already finalized");

    // 1. Verify TEE attestation (proves computation happened in genuine SGX)
    bool attestationOk = teeAttestor.verify(attestation, expectedMrEnclave, expectedMrSigner);
    if (!attestationOk) revert AttestationInvalid();

    // 2. Verify ZK proof (proves tally is correct without revealing individual votes)
    // Build public inputs for verification
    bytes memory publicInputs = abi.encode(
      keccak256(abi.encodePacked(proposalId)), // encryptedVotesCommitment
      forVotes,
      againstVotes,
      abstainVotes,
      keccak256(_proposalPublicKey[proposalId]) // sessionPublicKeyHash
    );
    
    (bool zkSuccess, bytes memory zkResult) = zkProofVerifier.call(
      abi.encodeWithSignature(
        "verifyTally(bytes,bytes)",
        zkProof,
        publicInputs
      )
    );
    
    if (!zkSuccess || (zkResult.length > 0 && !abi.decode(zkResult, (bool)))) {
      revert ZKProofVerificationFailed();
    }

    // Hook: Governor subclass can update proposal state
    _onTallyVerified(proposalId, zkProof, forVotes, againstVotes, abstainVotes);

    _finalized[proposalId] = true;
    emit TallyFinalized(proposalId, forVotes, againstVotes, abstainVotes);
  }
  
  /// @dev Verify Merkle proof for voter eligibility
  function verifyMerkleProof(
    bytes32[] calldata proof,
    bytes32 root,
    bytes32 leaf
  ) internal pure returns (bool) {
    bytes32 computedHash = leaf;
    
    for (uint256 i = 0; i < proof.length; i++) {
      bytes32 proofElement = proof[i];
      
      if (computedHash < proofElement) {
        computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
      } else {
        computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
      }
    }
    
    return computedHash == root;
  }

  /// @dev Governor subclass should update proposal state using provided aggregates
  function _onTallyVerified(
    uint256 proposalId,
    bytes calldata proof,
    uint256 forVotes,
    uint256 againstVotes,
    uint256 abstainVotes
  ) internal virtual;
}
