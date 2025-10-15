import sodium from 'libsodium-wrappers';

export type Hex = string;

export async function initSodium(): Promise<void> {
  if (!(sodium as any).ready) {
    await sodium.ready;
  }
}

export function hexToUint8Array(hex: Hex): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  return sodium.from_hex(clean);
}

export function uint8ArrayToHex(arr: Uint8Array): Hex {
  return '0x' + sodium.to_hex(arr);
}

// Encrypts a vote payload using libsodium sealed box with TEE session public key
export function encryptWithTeePublicKey(teePublicKeyHex: Hex, message: Uint8Array): Uint8Array {
  const pk = hexToUint8Array(teePublicKeyHex);
  return sodium.crypto_box_seal(message, pk);
}

export interface VotePayload {
  proposalId: string; // string to avoid JS number pitfalls
  choice: 'for' | 'against' | 'abstain';
  weight?: string; // optional weight
  nonce: string; // client nonce to avoid replay
}

export function encodeVotePayload(payload: VotePayload): Uint8Array {
  const json = JSON.stringify(payload);
  return new TextEncoder().encode(json);
}

export async function encryptVote(teePublicKeyHex: Hex, payload: VotePayload): Promise<Hex> {
  await initSodium();
  const msg = encodeVotePayload(payload);
  const sealed = encryptWithTeePublicKey(teePublicKeyHex, msg);
  return uint8ArrayToHex(sealed);
}
