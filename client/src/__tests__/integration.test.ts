import { describe, it, expect, beforeAll } from '@jest/globals';
import sodium from 'libsodium-wrappers';
import { encryptVote, hexToUint8Array, uint8ArrayToHex, type VotePayload } from '../crypto';

describe('End-to-End Integration', () => {
  let teeKeypair: sodium.KeyPair;
  let teePublicKeyHex: string;

  beforeAll(async () => {
    await sodium.ready;
    // Simulate TEE generating ephemeral keypair
    teeKeypair = sodium.crypto_box_keypair();
    teePublicKeyHex = uint8ArrayToHex(teeKeypair.publicKey);
  });

  describe('Complete Vote Flow', () => {
    it('should simulate full voting workflow: encrypt → submit → decrypt → tally', async () => {
      // ========================================
      // PHASE 1: Voters encrypt their votes
      // ========================================
      const votes: VotePayload[] = [
        { proposalId: '42', choice: 'for', weight: '1000', nonce: crypto.randomUUID() },
        { proposalId: '42', choice: 'for', weight: '2000', nonce: crypto.randomUUID() },
        { proposalId: '42', choice: 'against', weight: '1500', nonce: crypto.randomUUID() },
        { proposalId: '42', choice: 'abstain', weight: '500', nonce: crypto.randomUUID() },
        { proposalId: '42', choice: 'for', weight: '3000', nonce: crypto.randomUUID() },
      ];

      const encryptedVotes: string[] = [];
      for (const vote of votes) {
        const encrypted = await encryptVote(teePublicKeyHex, vote);
        encryptedVotes.push(encrypted);
        
        // Verify each vote is encrypted (hex format)
        expect(encrypted).toMatch(/^0x[0-9a-f]+$/);
      }

      // Verify all ciphertexts are unique (randomized encryption)
      const uniqueCiphertexts = new Set(encryptedVotes);
      expect(uniqueCiphertexts.size).toBe(encryptedVotes.length);

      // ========================================
      // PHASE 2: Smart contract emits events
      // (In real app: contract stores events on-chain)
      // ========================================
      console.log(`📝 ${encryptedVotes.length} encrypted votes submitted to contract`);

      // ========================================
      // PHASE 3: TEE decrypts and tallies
      // ========================================
      const tally = { for: 0, against: 0, abstain: 0 };

      for (const encryptedHex of encryptedVotes) {
        // TEE decrypts each vote
        const ciphertext = hexToUint8Array(encryptedHex);
        const decrypted = sodium.crypto_box_seal_open(
          ciphertext,
          teeKeypair.publicKey,
          teeKeypair.privateKey
        );

        const vote: VotePayload = JSON.parse(new TextDecoder().decode(decrypted));
        
        // Verify vote structure
        expect(vote.proposalId).toBe('42');
        expect(['for', 'against', 'abstain']).toContain(vote.choice);
        expect(vote.weight).toBeDefined();

        // Tally the vote
        const weight = parseInt(vote.weight || '0');
        if (vote.choice === 'for') tally.for += weight;
        if (vote.choice === 'against') tally.against += weight;
        if (vote.choice === 'abstain') tally.abstain += weight;
      }

      // ========================================
      // PHASE 4: Verify final tally
      // ========================================
      console.log('📊 Final Tally:', tally);
      
      expect(tally.for).toBe(6000);     // 1000 + 2000 + 3000
      expect(tally.against).toBe(1500);  // 1500
      expect(tally.abstain).toBe(500);   // 500

      const totalWeight = tally.for + tally.against + tally.abstain;
      expect(totalWeight).toBe(8000);

      // ========================================
      // SUCCESS: Privacy preserved, results verified!
      // ========================================
      console.log('✅ Vote privacy maintained: individual votes never exposed');
      console.log('✅ Tally verified: aggregate results computed correctly');
    });

    it('should prevent decryption with wrong private key', async () => {
      // Encrypt a vote
      const vote: VotePayload = {
        proposalId: '99',
        choice: 'for',
        nonce: crypto.randomUUID(),
      };
      const encrypted = await encryptVote(teePublicKeyHex, vote);

      // Try to decrypt with a different keypair (attacker scenario)
      const attackerKeypair = sodium.crypto_box_keypair();
      
      expect(() => {
        sodium.crypto_box_seal_open(
          hexToUint8Array(encrypted),
          attackerKeypair.publicKey,
          attackerKeypair.privateKey
        );
      }).toThrow();

      console.log('✅ Attacker cannot decrypt votes without TEE private key');
    });

    it('should handle high vote volume efficiently', async () => {
      const startTime = Date.now();
      const numVotes = 100;
      const votes: VotePayload[] = [];

      // Generate and encrypt 100 votes
      for (let i = 0; i < numVotes; i++) {
        const vote: VotePayload = {
          proposalId: '1000',
          choice: i % 3 === 0 ? 'for' : i % 3 === 1 ? 'against' : 'abstain',
          weight: '1',
          nonce: crypto.randomUUID(),
        };
        votes.push(vote);
      }

      const encrypted = await Promise.all(
        votes.map(v => encryptVote(teePublicKeyHex, v))
      );

      const encryptTime = Date.now() - startTime;
      console.log(`⚡ Encrypted ${numVotes} votes in ${encryptTime}ms (${(encryptTime/numVotes).toFixed(2)}ms per vote)`);

      // Decrypt and tally
      const decryptStart = Date.now();
      let forCount = 0, againstCount = 0, abstainCount = 0;

      for (const enc of encrypted) {
        const decrypted = sodium.crypto_box_seal_open(
          hexToUint8Array(enc),
          teeKeypair.publicKey,
          teeKeypair.privateKey
        );
        const v: VotePayload = JSON.parse(new TextDecoder().decode(decrypted));
        if (v.choice === 'for') forCount++;
        if (v.choice === 'against') againstCount++;
        if (v.choice === 'abstain') abstainCount++;
      }

      const decryptTime = Date.now() - decryptStart;
      console.log(`⚡ Decrypted and tallied ${numVotes} votes in ${decryptTime}ms (${(decryptTime/numVotes).toFixed(2)}ms per vote)`);

      expect(forCount + againstCount + abstainCount).toBe(numVotes);
      expect(encryptTime).toBeLessThan(10000); // Should be < 10s for 100 votes
      expect(decryptTime).toBeLessThan(5000);  // Should be < 5s for 100 votes
    });
  });
});

