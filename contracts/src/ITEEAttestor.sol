// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITEEAttestor {
  // Verifies an attestation blob for a specific measurement and returns true if valid
  function verify(bytes calldata attestation, bytes32 expectedMrEnclave, bytes32 expectedMrSigner) external view returns (bool);
}
