import { Keypair, PublicKey } from "@solana/web3.js";

import { describeError } from "../chain/confirm";
import { GuardClient, SendOutcome } from "../guard/client";

/** Restores a revoked demo agent and checks the entry on-chain afterward. */
export async function restoreAgentEntry(
  client: Pick<GuardClient, "entry" | "addEntry">,
  owner: Keypair,
  agent: PublicKey
): Promise<{ alreadyPresent: boolean; outcome: SendOutcome | null }> {
  let alreadyPresent = false;
  try {
    alreadyPresent = (await client.entry("agent", agent)).member;
  } catch {
    // A failed read is not proof of absence. Try the restore write, then
    // require a successful read before calling the agent restored.
  }
  if (alreadyPresent) return { alreadyPresent: true, outcome: null };

  let outcome: SendOutcome | null = null;
  let sendError: unknown = null;
  try {
    outcome = await client.addEntry(owner, "agent", agent);
  } catch (err) {
    sendError = err;
  }
  let present: boolean;
  try {
    present = (await client.entry("agent", agent)).member;
  } catch (err) {
    throw new Error(
      `could not verify the agent entry after restore: ${describeError(err)}`
    );
  }
  if (!present)
    throw new Error(
      `the agent entry is still missing after restore: ${
        outcome?.error ??
        (sendError ? describeError(sendError) : "check the guard")
      }`
    );
  return { alreadyPresent: false, outcome };
}
