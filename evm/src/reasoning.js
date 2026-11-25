// llm reasoning layer - the second pass.
// only runs when the deterministic lanes are alarmed (bytecode HIGH) or unsure
// (ASK_HUMAN). point is to cut false positives/negatives: confirm a real trap
// or clear a benign one by actually reasoning about the bytecode.
//
// goes through the claude code cli in headless mode (claude -p), so no api key.
// wrapped defensively - if the cli is missing or errors we return
// available:false and the engine falls back to the deterministic verdict, so
// the demo never dies on stage.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileP = promisify(execFile);
const TIMEOUT_MS = 60_000;

function buildPrompt({ recipient, bytecode, hits, mode }) {
  const tripped =
    Object.entries(hits)
      .map(([name, h]) => `${name} x${h.count} - ${h.note}`)
      .join('; ') || 'none';

  const task =
    mode === 'confirm'
      ? 'The deterministic filter flagged this as HIGH risk (a BLOCK candidate). Decide whether it is GENUINELY malicious for someone SENDING funds to this address, or a benign false alarm.'
      : 'The deterministic filter is UNCERTAIN about this payment. Analyze the bytecode and summarize what this contract can do, so a human can decide, informed.';

  const codeLine =
    bytecode && bytecode !== '0x'
      ? bytecode
      : '(none - recipient is an EOA with no contract code)';

  return `You are a smart-contract security analyzer inside a payment firewall for AI agents.

Recipient: ${recipient}
Recipient EVM runtime bytecode: ${codeLine}
Deterministic heuristics tripped: ${tripped}

${task}

Reply with ONLY a JSON object - no markdown fences, no prose outside it - exactly:
{"malicious": true|false, "confidence": "low"|"medium"|"high", "reason": "one or two plain-English sentences"}`;
}

// grab the first {...} block in case the model adds any stray text around it
function extractJson(stdout) {
  const match = stdout.match(/\{[\s\S]*\}/);
  if (!match) throw new Error('no JSON object found in LLM output');
  return JSON.parse(match[0]);
}

// mode: 'confirm' (is this really malicious?) or 'analyze' (explain it for a human)
export async function reason({ recipient, bytecode, hits, mode }) {
  const prompt = buildPrompt({ recipient, bytecode, hits, mode });
  try {
    const { stdout } = await execFileP('claude', ['-p', prompt], {
      timeout: TIMEOUT_MS,
      maxBuffer: 1024 * 1024,
    });
    const parsed = extractJson(stdout);
    return {
      available: true,
      malicious: Boolean(parsed.malicious),
      confidence: parsed.confidence ?? 'unknown',
      reason: String(parsed.reason ?? '').trim(),
    };
  } catch (err) {
    // cli missing / timeout / bad output -> engine falls back deterministically
    return {
      available: false,
      malicious: null,
      confidence: null,
      reason: null,
      error: err.shortMessage || err.message,
    };
  }
}
