import { describe, it, expect, beforeAll } from '@jest/globals';
import sodium from 'libsodium-wrappers';
import {
  initSodium,
  hexToUint8Array,
  uint8ArrayToHex,
  encryptWithTeePublicKey,
  encodeVotePayload,
  encryptVote,
  type VotePayload,
} from '../crypto';

describe('Crypto Module', () => {
  beforeAll(async () => {
    await sodium.ready;
    await initSodium();
  });

  describe('hexToUint8Array', () => {
    it('should convert hex string to Uint8Array', () => {
      const hex = '0x48656c6c6f';
      const result = hexToUint8Array(hex);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(Array.from(result)).toEqual([72, 101, 108, 108, 111]); // "Hello"
    });

    it('should handle hex without 0x prefix', () => {
      const hex = '48656c6c6f';
      const result = hexToUint8Array(hex);
      expect(Array.from(result)).toEqual([72, 101, 108, 108, 111]);
    });
  });

  describe('uint8ArrayToHex', () => {
    it('should convert Uint8Array to hex string with 0x prefix', () => {
      const arr = new Uint8Array([72, 101, 108, 108, 111]);
      const result = uint8ArrayToHex(arr);
      expect(result).toBe('0x48656c6c6f');
    });
  });

  describe('encodeVotePayload', () => {
    it('should encode vote payload as JSON bytes', () => {
      const payload: VotePayload = {
        proposalId: '123',
        choice: 'for',
        weight: '1000',
        nonce: 'abc123',
      };
      const encoded = encodeVotePayload(payload);
      expect(encoded).toBeInstanceOf(Uint8Array);
      
      const decoded = JSON.parse(new TextDecoder().decode(encoded));
      expect(decoded).toEqual(payload);
    });

    it('should handle minimal payload without weight', () => {
      const payload: VotePayload = {
        proposalId: '456',
        choice: 'against',
        nonce: 'xyz789',
      };
      const encoded = encodeVotePayload(payload);
      const decoded = JSON.parse(new TextDecoder().decode(encoded));
      expect(decoded.proposalId).toBe('456');
      expect(decoded.choice).toBe('against');
    });
  });

  describe('encryptWithTeePublicKey', () => {
    it('should encrypt message using sealed box', async () => {
      // Generate a test keypair
      const keypair = sodium.crypto_box_keypair();
      const publicKeyHex = uint8ArrayToHex(keypair.publicKey);
      
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const encrypted = encryptWithTeePublicKey(publicKeyHex, message);
      
      expect(encrypted).toBeInstanceOf(Uint8Array);
      expect(encrypted.length).toBeGreaterThan(message.length); // Should be larger due to encryption overhead
      
      // Verify we can decrypt with the private key
      const decrypted = sodium.crypto_box_seal_open(
        encrypted,
        keypair.publicKey,
        keypair.privateKey
      );
      expect(Array.from(decrypted)).toEqual(Array.from(message));
    });
  });

  describe('encryptVote - End-to-End', () => {
    it('should encrypt a complete vote payload', async () => {
      // Generate a test TEE keypair
      const keypair = sodium.crypto_box_keypair();
      const teePublicKeyHex = uint8ArrayToHex(keypair.publicKey);
      
      const payload: VotePayload = {
        proposalId: '999',
        choice: 'abstain',
        weight: '5000',
        nonce: crypto.randomUUID(),
      };
      
      const ciphertextHex = await encryptVote(teePublicKeyHex, payload);
      
      // Verify format
      expect(ciphertextHex).toMatch(/^0x[0-9a-f]+$/);
      
      // Decrypt and verify
      const ciphertext = hexToUint8Array(ciphertextHex);
      const decrypted = sodium.crypto_box_seal_open(
        ciphertext,
        keypair.publicKey,
        keypair.privateKey
      );
      
      const decryptedPayload = JSON.parse(new TextDecoder().decode(decrypted));
      expect(decryptedPayload).toEqual(payload);
    });

    it('should produce different ciphertexts for same payload (randomized)', async () => {
      const keypair = sodium.crypto_box_keypair();
      const teePublicKeyHex = uint8ArrayToHex(keypair.publicKey);
      
      const payload: VotePayload = {
        proposalId: '111',
        choice: 'for',
        nonce: 'test123',
      };
      
      const ciphertext1 = await encryptVote(teePublicKeyHex, payload);
      const ciphertext2 = await encryptVote(teePublicKeyHex, payload);
      
      // Should be different due to randomized encryption
      expect(ciphertext1).not.toBe(ciphertext2);
      
      // But both should decrypt to same payload
      const decrypted1 = sodium.crypto_box_seal_open(
        hexToUint8Array(ciphertext1),
        keypair.publicKey,
        keypair.privateKey
      );
      const decrypted2 = sodium.crypto_box_seal_open(
        hexToUint8Array(ciphertext2),
        keypair.publicKey,
        keypair.privateKey
      );
      
      expect(new TextDecoder().decode(decrypted1)).toBe(new TextDecoder().decode(decrypted2));
    });
  });
});

