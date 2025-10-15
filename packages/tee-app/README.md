# TEE Application for Private Tally

C++ application running in iExec TEE (Trusted Execution Environment) for confidential vote decryption and tallying.

## Architecture

1. **Key Generation**: Ephemeral keypair per voting session (never leaves TEE)
2. **Vote Decryption**: Unseals encrypted votes using libsodium sealed boxes
3. **Tallying**: Aggregates votes within secure enclave
4. **Attestation**: Produces cryptographic proof of correct execution
5. **Result Publication**: Only aggregate tallies exit the TEE

## Building

### Local (for development)
```bash
cmake -S . -B build
cmake --build build
./build/tee-app
```

### Docker (for iExec deployment)
```bash
docker build -t privatetally/tee-app:latest .
docker run privatetally/tee-app:latest
```

## iExec Integration

1. Build and push Docker image
2. Register app on iExec marketplace
3. Update `iexec.json` with app address and mrenclave
4. Deploy to iExec scheduler

## Security Considerations

- Private keys generated inside TEE, never exported
- All decryption happens in secure enclave
- Attestation verifies correct execution
- No persistent storage of votes or keys
- Time-locked session keys

