import { useCallback, useState } from 'react';
import { encryptVote, VotePayload } from './crypto';

export function useEncryptVote(teePublicKeyHex: string) {
  const [ciphertext, setCiphertext] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);

  const run = useCallback(async (payload: VotePayload) => {
    setIsEncrypting(true);
    setError(null);
    try {
      const ct = await encryptVote(teePublicKeyHex, payload);
      setCiphertext(ct);
      return ct;
    } catch (e: any) {
      const msg = e?.message || 'Encryption failed';
      setError(msg);
      throw e;
    } finally {
      setIsEncrypting(false);
    }
  }, [teePublicKeyHex]);

  return { run, ciphertext, error, isEncrypting };
}
