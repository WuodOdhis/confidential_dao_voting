// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PrivateGovernor} from "../src/PrivateGovernor.sol";
import {ITEEAttestor} from "../src/ITEEAttestor.sol";
import {IPrivateGovernor} from "../src/IPrivateGovernor.sol";

contract MockAttestor is ITEEAttestor {
  bool public result = true;
  function set(bool r) external { result = r; }
  function verify(bytes calldata, bytes32, bytes32) external view returns (bool) { return result; }
}

contract MockZKVerifier {
  function verifyTally(bytes calldata, bytes calldata) external pure returns (bool) {
    return true; // Mock always accepts
  }
}

contract PrivateGovernorImpl is PrivateGovernor {
  constructor(
    ITEEAttestor a, 
    bytes32 m1, 
    bytes32 m2, 
    address f, 
    address zkVerifier,
    bytes32 merkleRoot
  ) PrivateGovernor("PrivateGovernor", a, m1, m2, f, zkVerifier, merkleRoot) {}

  function name() public pure override returns (string memory) { return "PrivateGovernor"; }
  function votingDelay() public pure override returns (uint256) { return 1; }
  function votingPeriod() public pure override returns (uint256) { return 10; }
  function quorum(uint256) public pure override returns (uint256) { return 0; }

  // Governor abstract functions that need implementation
  function clock() public view override returns (uint48) { return uint48(block.timestamp); }
  function CLOCK_MODE() public pure override returns (string memory) { return "mode=timestamp"; }
  function COUNTING_MODE() public pure override returns (string memory) { return "support=bravo&quorum=for,abstain"; }

  function _getVotes(address account, uint256 timepoint, bytes memory params) internal view override returns (uint256) {
    // For testing, return 1 vote for any account with balance
    return 1;
  }

  function _quorumReached(uint256 proposalId) internal view override returns (bool) {
    // Simple quorum: at least 1 vote
    return true;
  }

  function _voteSucceeded(uint256 proposalId) internal view override returns (bool) {
    // Simple success: more for than against
    return true;
  }

  function _countVote(
    uint256 proposalId,
    address account,
    uint8 support,
    uint256 weight,
    bytes memory params
  ) internal override {
    // For testing, just count the vote (no return value needed)
  }

  function hasVoted(uint256 proposalId, address account) public view override returns (bool) {
    // For testing, assume no one has voted yet
    return false;
  }

  function _onTallyVerified(uint256, bytes calldata, uint256, uint256, uint256) internal override {}
}

contract PrivateGovernorTest is Test {
  MockAttestor att;
  MockZKVerifier zkVerifier;
  PrivateGovernorImpl gov;
  bytes32 merkleRoot;

  function setUp() public {
    att = new MockAttestor();
    zkVerifier = new MockZKVerifier();
    merkleRoot = keccak256(abi.encodePacked(address(this))); // Simple merkle root for testing
    gov = new PrivateGovernorImpl(
      att, 
      bytes32(uint256(1)), 
      bytes32(uint256(2)), 
      address(this),
      address(zkVerifier),
      merkleRoot
    );
  }

  function testPublishAndSubmit() public {
    bytes memory pk = hex"abcd";
    gov.publishSessionPublicKey(1, pk, hex"11");
    bytes memory stored = gov.sessionPublicKey(1);
    assertEq(keccak256(stored), keccak256(pk));

    // Generate nullifier for this vote
    bytes32 nullifier = keccak256(abi.encodePacked("voter_secret", uint256(1)));
    
    // Create merkle proof (for testing, just empty array since we set simple root)
    bytes32[] memory merkleProof = new bytes32[](0);

    vm.expectEmit(true, true, false, true);
    emit IPrivateGovernor.EncryptedVoteSubmitted(1, nullifier, hex"beef");
    gov.submitEncryptedVote(1, hex"beef", nullifier, merkleProof);
  }

  function testFinalize() public {
    gov.publishSessionPublicKey(1, hex"aa", hex"11");
    vm.expectEmit(true, true, false, true);
    emit IPrivateGovernor.TallyFinalized(1, 5, 3, 2);
    gov.finalizeTally(1, 5, 3, 2, hex"", hex"22");
  }
}
