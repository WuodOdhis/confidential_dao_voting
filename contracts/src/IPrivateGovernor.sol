// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPrivateGovernor {
  event SessionPublicKeyPublished(uint256 indexed proposalId, bytes teePublicKey);
  event EncryptedVoteSubmitted(uint256 indexed proposalId, bytes32 indexed nullifier, bytes ciphertext);
  event TallyFinalized(uint256 indexed proposalId, uint256 forVotes, uint256 againstVotes, uint256 abstainVotes);

  function publishSessionPublicKey(uint256 proposalId, bytes calldata teePublicKey, bytes calldata attestation) external;
  function submitEncryptedVote(
    uint256 proposalId, 
    bytes calldata ciphertext,
    bytes32 nullifier,
    bytes32[] calldata merkleProof
  ) external;
  function finalizeTally(
    uint256 proposalId,
    uint256 forVotes,
    uint256 againstVotes,
    uint256 abstainVotes,
    bytes calldata zkProof,
    bytes calldata attestation
  ) external;
  function sessionPublicKey(uint256 proposalId) external view returns (bytes memory);
}
