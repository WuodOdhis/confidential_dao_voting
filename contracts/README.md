# Contracts

- Foundry project
- Extends OpenZeppelin  with encrypted vote handling and TEE attestation verification

Setup:
- install Foundry: https://book.getfoundry.sh
- forge init (already structured), then add deps:
  - 
  - 
- run tests: Compiler run failed:
Error (6275): Source "forge-std/Script.sol" not found: File not found. Searched the following locations: "/home/badman/Projects/confidential_vote".
ParserError: Source "forge-std/Script.sol" not found: File not found. Searched the following locations: "/home/badman/Projects/confidential_vote".
 --> contracts/script/Deploy.s.sol:4:1:
  |
4 | import "forge-std/Script.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error (6275): Source "@openzeppelin/contracts/governance/Governor.sol" not found: File not found. Searched the following locations: "/home/badman/Projects/confidential_vote".
ParserError: Source "@openzeppelin/contracts/governance/Governor.sol" not found: File not found. Searched the following locations: "/home/badman/Projects/confidential_vote".
 --> contracts/src/PrivateGovernor.sol:4:1:
  |
4 | import {Governor} from "@openzeppelin/contracts/governance/Governor.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error (6275): Source "@openzeppelin/contracts/utils/introspection/ERC165.sol" not found: File not found. Searched the following locations: "/home/badman/Projects/confidential_vote".
ParserError: Source "@openzeppelin/contracts/utils/introspection/ERC165.sol" not found: File not found. Searched the following locations: "/home/badman/Projects/confidential_vote".
 --> contracts/src/PrivateGovernor.sol:5:1:
  |
5 | import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error (6275): Source "forge-std/Test.sol" not found: File not found. Searched the following locations: "/home/badman/Projects/confidential_vote".
ParserError: Source "forge-std/Test.sol" not found: File not found. Searched the following locations: "/home/badman/Projects/confidential_vote".
 --> contracts/test/PrivateGovernor.t.sol:4:1:
  |
4 | import "forge-std/Test.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
