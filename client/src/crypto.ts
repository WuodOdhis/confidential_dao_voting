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

export type VoteChoice = 'for' | 'against' | 'abstain';

export interface VotePayload {
  proposalId: string; // string to avoid JS number pitfalls
  choice: VoteChoice;
  weight?: string; // optional weight
  nonce: string; // client nonce to avoid replay
  voterSecret?: string; // Secret for nullifier generation (keeps voter anonymous)
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

// Generate nullifier from voter secret and proposal ID
// Nullifier = H(voterSecret || proposalId)
// This allows anonymous voting while preventing double-voting
export async function generateNullifier(voterSecret: string, proposalId: string): Promise<Hex> {
  await initSodium();
  const combined = new TextEncoder().encode(voterSecret + '||' + proposalId);
  const hash = sodium.crypto_generichash(32, combined);
  return uint8ArrayToHex(hash);
}

// Generate Merkle proof for voter eligibility
// In production, this would query an off-chain service that has the full Merkle tree
export interface MerkleProof {
  leaf: Hex;
  proof: Hex[];
  root: Hex;
}

export async function generateMerkleProof(
  voterAddress: string,
  eligibleVoters: string[]
): Promise<MerkleProof> {
  await initSodium();
  
  // Build Merkle tree
  const leaves = eligibleVoters.map(addr => 
    uint8ArrayToHex(sodium.crypto_generichash(32, new TextEncoder().encode(addr)))
  );
  
  const leaf = uint8ArrayToHex(sodium.crypto_generichash(32, new TextEncoder().encode(voterAddress)));
  const leafIndex = leaves.indexOf(leaf);
  
  if (leafIndex === -1) {
    throw new Error('Voter not in eligible list');
  }
  
  // Build proof path (simplified - in production use proper Merkle tree library)
  const proof: Hex[] = [];
  let currentLevel = leaves;
  let currentIndex = leafIndex;
  
  while (currentLevel.length > 1) {
    const newLevel: string[] = [];
    
    for (let i = 0; i < currentLevel.length; i += 2) {
      if (i + 1 < currentLevel.length) {
        const left = hexToUint8Array(currentLevel[i]);
        const right = hexToUint8Array(currentLevel[i + 1]);
        const combined = new Uint8Array([...left, ...right]);
        const hash = sodium.crypto_generichash(32, combined);
        newLevel.push(uint8ArrayToHex(hash));
        
        // Add sibling to proof
        if (currentIndex === i) {
          proof.push(currentLevel[i + 1]);
        } else if (currentIndex === i + 1) {
          proof.push(currentLevel[i]);
        }
      } else {
        newLevel.push(currentLevel[i]);
      }
    }
    
    currentIndex = Math.floor(currentIndex / 2);
    currentLevel = newLevel;
  }
  
  return {
    leaf,
    proof,
    root: currentLevel[0]
  };
}
