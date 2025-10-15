# Architecture Documentation

## System Components

```
┌─────────────┐
│   Voter     │
│  (Client)   │
└──────┬──────┘
       │ 1. Get TEE public key
       │ 2. Encrypt vote
       │ 3. Submit to chain
       ▼
┌─────────────────────────┐
│  PrivateGovernor.sol    │
│  (Arbitrum L2)          │
│  - Stores session keys  │
│  - Emits vote events    │
│  - Verifies attestation │
└────────┬────────────────┘
         │ 4. TEE reads encrypted votes
         │ 5. Decrypts in enclave
         │ 6. Produces tally + proof
         ▼
┌─────────────────────────┐
│   TEE Application       │
│   (iExec Enclave)       │
│   - Generate keypair    │
│   - Decrypt votes       │
│   - Aggregate tallies   │
│   - Sign attestation    │
└────────┬────────────────┘
         │ 7. Submit aggregate results
         ▼
┌─────────────────────────┐
│  PrivateGovernor.sol    │
│  - Verify attestation   │
│  - Finalize tally       │
│  - Update proposal state│
└─────────────────────────┘
```

## Data Flow

### Phase 1: Voting Session Initialization
1. DAO creates proposal on-chain (standard Governor flow)
2. TEE application generates ephemeral keypair inside enclave
3. TEE publishes public key + attestation on-chain
4. Smart contract verifies attestation and stores public key
5. Voters can now retrieve public key for encryption

### Phase 2: Vote Submission
1. Voter constructs vote payload:
   ```json
   {
     "proposalId": "123",
     "choice": "for",
     "weight": "1000",
     "nonce": "random_hex"
   }
   ```
2. Client encrypts payload with TEE public key (libsodium sealed box)
3. Voter submits encrypted vote to smart contract
4. Smart contract emits `EncryptedVoteSubmitted` event (no state changes)

### Phase 3: Tallying (Inside TEE)
1. TEE application reads all `EncryptedVoteSubmitted` events from chain
2. Decrypts each vote using ephemeral private key (inside enclave)
3. Validates vote payload (proposalId, signature, nonce)
4. Aggregates tallies: `(forVotes, againstVotes, abstainVotes)`
5. Generates cryptographic proof of correct execution
6. Signs result with TEE attestation

### Phase 4: Result Finalization
1. TEE or authorized relayer submits tally + attestation to chain
2. Smart contract verifies attestation
3. Smart contract validates proof (if using zk-SNARK or similar)
4. Updates proposal state with aggregate results
5. Emits `TallyFinalized` event

## Contract Interfaces

### IPrivateGovernor
```solidity
function publishSessionPublicKey(uint256 proposalId, bytes calldata teePublicKey, bytes calldata attestation) external;
function submitEncryptedVote(uint256 proposalId, bytes calldata ciphertext) external;
function finalizeTally(uint256 proposalId, uint256 forVotes, uint256 againstVotes, uint256 abstainVotes, bytes calldata proof, bytes calldata attestation) external;
```

### ITEEAttestor
```solidity
function verify(bytes calldata attestation, bytes32 expectedMrEnclave, bytes32 expectedMrSigner) external view returns (bool);
```

## Client Library API

### Encryption
```typescript
import { encryptVote } from '@privatetally/client';

const ciphertext = await encryptVote(teePublicKeyHex, {
  proposalId: '123',
  choice: 'for',
  weight: '1000',
  nonce: generateNonce()
});
```

### React Hook
```typescript
import { useEncryptVote } from '@privatetally/client';

const { run, ciphertext, error, isEncrypting } = useEncryptVote(teePublicKeyHex);

// In component
await run({ proposalId, choice, weight, nonce });
```

## TEE Application

### Inputs
- Encrypted votes (read from chain events)
- Proposal ID
- Voting period parameters

### Outputs
- Aggregate tally results
- Cryptographic proof
- TEE attestation signature

### Security Properties
1. **Confidentiality**: Votes never leave enclave in plaintext
2. **Integrity**: Attestation proves correct computation
3. **Availability**: Multiple TEE instances can run same computation

## Gas Optimization

### Arbitrum L2 Benefits
- ~100x cheaper than Ethereum mainnet
- Sub-$0.50 per vote target achieved
- Fast finality (2-3 seconds)

### Contract Optimizations
- Event-only vote storage (no SSTORE)
- Immutable attestation parameters
- Single finalizer address (no access control overhead)

## Deployment Checklist

- [ ] Deploy MockAttestor or integrate real SGX verifier
- [ ] Deploy PrivateGovernor with token voting
- [ ] Build and register TEE app on iExec
- [ ] Update mrenclave/mrsigner in contract
- [ ] Publish client library to npm
- [ ] Configure CI/CD pipelines
- [ ] Run security audits
- [ ] Deploy to Arbitrum mainnet

