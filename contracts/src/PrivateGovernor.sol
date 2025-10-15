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

  ITEEAttestor public immutable teeAttestor;
  bytes32 public immutable expectedMrEnclave; // TEE measurement for the app
  bytes32 public immutable expectedMrSigner;  // TEE signer/IAS measurement

  // proposalId => TEE session public key (libsodium public key)
  mapping(uint256 => bytes) private _proposalPublicKey;

  // proposalId => has been finalized
  mapping(uint256 => bool) private _finalized;

  // address allowed to finalize tallies (e.g., relayer owned by TEE scheduler)
  address public immutable tallyFinalizer;

  constructor(
    string memory name_,
    ITEEAttestor _teeAttestor,
    bytes32 _expectedMrEnclave,
    bytes32 _expectedMrSigner,
    address _tallyFinalizer
  ) Governor(name_) {
    teeAttestor = _teeAttestor;
    expectedMrEnclave = _expectedMrEnclave;
    expectedMrSigner = _expectedMrSigner;
    tallyFinalizer = _tallyFinalizer;
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

  function submitEncryptedVote(uint256 proposalId, bytes calldata ciphertext) external override {
    if (_proposalPublicKey[proposalId].length == 0) revert SessionKeyNotSet(proposalId);
    // Store an event-only trail to avoid leaking vote content/state on-chain
    emit EncryptedVoteSubmitted(proposalId, _msgSender(), ciphertext);
  }

  function finalizeTally(
    uint256 proposalId,
    uint256 forVotes,
    uint256 againstVotes,
    uint256 abstainVotes,
    bytes calldata proof,
    bytes calldata attestation
  ) external override {
    if (_msgSender() != tallyFinalizer) revert OnlyTEEFinalizer();
    if (_finalized[proposalId]) revert("Already finalized");

    // Verify TEE attestation again and proof of correct tallying. For now, rely on attestation.
    bool ok = teeAttestor.verify(attestation, expectedMrEnclave, expectedMrSigner);
    if (!ok) revert AttestationInvalid();

    // Hook: verify proof bytes if integrating zk-proof or transcript validation
    _onTallyVerified(proposalId, proof, forVotes, againstVotes, abstainVotes);

    _finalized[proposalId] = true;
    emit TallyFinalized(proposalId, forVotes, againstVotes, abstainVotes);
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
