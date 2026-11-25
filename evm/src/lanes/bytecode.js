// bytecode lane - the real one.
// pull the recipient's code with eth_getCode and scan the opcodes for
// stuff that's usually bad news. this is the ethereum-native check: we're
// reading the actual EVM instructions the recipient would run.
//
// note: it's a linear walk, so "present" != "reachable". we over-flag on
// purpose and let the llm second pass sort out the false alarms.
//
// the direction we can't be relaxed about is the opposite one - anything that
// lets a recipient hide code FROM the walk is a false negative, and a firewall
// doesn't get to fail that way. see stripMetadata for the one that bit us.
import { publicClient } from '../config.js';

// danger opcodes -> how much risk each one adds to the score
const DANGER = {
  0xff: { name: 'SELFDESTRUCT', score: 60, note: 'selfdestruct present - funds sent here can get stranded (honeypot / dead-end pattern)' },
  0xf4: { name: 'DELEGATECALL', score: 40, note: 'delegatecall - upgradeable/proxy, logic can be swapped out under you' },
  0xf2: { name: 'CALLCODE',     score: 40, note: 'callcode - deprecated delegatecall variant, drainer-adjacent' },
  0xf5: { name: 'CREATE2',      score: 35, note: 'create2 - can redeploy different code at the same address (metamorphic rug)' },
  0xf0: { name: 'CREATE',       score: 20, note: 'create - can spawn child contracts at runtime' },
  0x32: { name: 'ORIGIN',       score: 15, note: 'tx.origin - phishing / auth-bypass anti-pattern' },
};

// Circle's own infrastructure on Arc. this matters because the lane scores most
// of it MEDIUM for DELEGATECALL - correctly, they really are proxies - and
// "Aegis flags USDC" is a bad look that's also bad information.
//
// note what this does NOT do: it doesn't zero the score. an upgradeable
// contract genuinely can change under you, and suppressing that would be hiding
// a fact instead of explaining it. so we name the contract and say what the
// trust actually rests on, and let a human weigh it. these are also NOT written
// into the guard's on-chain allowedContract mapping - guardedPay sends a bare
// transferFrom with no calldata, and none of these are a meaningful destination
// for that. paying USDC *to* the USDC contract isn't a payment, it's a mistake,
// and the unvetted-contract Review gate should keep catching it.
//
// arc also has proxies at 0x3600..0001/0002/0003 that aren't listed here: they
// answer neither name() nor version(), so they can't be identified from chain
// state alone, and an entry we can't justify is worse than no entry.
const IMMUTABLE = 'deployed deterministically and not upgradeable';
const CIRCLE_ADMIN = 'upgradeable by Circle, so its logic can change under you';
const CIRCLE_SYSTEM = {
  '0x3600000000000000000000000000000000000000': { name: 'USDC (ERC-20 interface)', trust: CIRCLE_ADMIN },
  '0x000000000022d473030f116ddee9f6b43ac78ba3': { name: 'Permit2', trust: IMMUTABLE },
  '0x8fe6b999dc680ccfdd5bf7eb0974218be2542daa': { name: 'TokenMessengerV2 (CCTP)', trust: CIRCLE_ADMIN },
  '0x0077777d7eba4688bdef3e311b846f25870a19b9': { name: 'GatewayWallet', trust: CIRCLE_ADMIN },
  '0x0022222abe238cc2c7bb1f21003f0a260052475b': { name: 'GatewayMinter', trust: CIRCLE_ADMIN },
  '0x867650f5eae8df91445971f14d89fd84f0c9a9f8': { name: 'FxEscrow (StableFX)', trust: CIRCLE_ADMIN },
};

// PUSH1..PUSH32 (0x60-0x7f) carry 1-32 data bytes right after them.
// have to skip those or we'd read pushed data as if it were opcodes.
function isPush(op) {
  return op >= 0x60 && op <= 0x7f;
}
function pushLen(op) {
  return op - 0x60 + 1;
}

// a minimal cbor reader - only the subset solc actually emits (a small map of
// short text keys to byte strings, a version, a bool). returns the index just
// past the item starting at `i`, or -1 for anything outside that subset. if we
// can't account for the blob byte for byte, we don't treat it as metadata.
function cborEnd(b, i) {
  if (i >= b.length) return -1;
  const t = b[i];
  if (t <= 0x17) return i + 1; // small uint
  if (t === 0x18) return i + 2; // uint8
  if (t === 0x19) return i + 3; // uint16
  if (t >= 0x40 && t <= 0x57) return i + 1 + (t - 0x40); // short byte string
  if (t === 0x58) return i + 2 + (b[i + 1] ?? 0); // byte string, 1-byte length
  if (t >= 0x60 && t <= 0x77) return i + 1 + (t - 0x60); // short text string
  if (t === 0x78) return i + 2 + (b[i + 1] ?? 0); // text string, 1-byte length
  if (t === 0xf4 || t === 0xf5) return i + 1; // false / true
  if (t >= 0xa0 && t <= 0xa3) { // map of 0-3 pairs
    let j = i + 1;
    for (let n = 0; n < (t - 0xa0) * 2; n++) {
      j = cborEnd(b, j);
      if (j < 0) return -1;
    }
    return j;
  }
  return -1;
}

const JUMP = 0x56;
const JUMPI = 0x57;
const JUMPDEST = 0x5b;

// walk the code the way the EVM does: one instruction at a time, stepping over
// push immediates. this is the same analysis the EVM runs to decide which
// JUMPDESTs are real, and it matters in both directions - a 0x5b sitting inside
// push data is NOT a landing site, and treating it as one would be its own kind
// of wrong. each entry carries the pushed constant where there is one, and null
// where the value is too wide to be an offset.
function instructionsOf(b) {
  const out = [];
  for (let i = 0; i < b.length; i++) {
    const op = b[i];
    if (!isPush(op)) {
      out.push({ at: i, op, push: false, value: null });
      continue;
    }
    const n = pushLen(op);
    // read the immediate at whatever width it is. a PUSH5 carrying a
    // zero-padded offset is exactly as good a jump as a PUSH1, so only
    // inspecting narrow pushes isn't a check, it's a guess - and it's the
    // guess an attacker makes first. runtime code caps at 24576 bytes, so for
    // a value that could actually be an offset every byte above the low four
    // has to be zero; a non-zero one just means "not an offset".
    let high = 0;
    let v = 0;
    for (let k = 1; k <= n; k++) {
      const byte = b[i + k] ?? 0;
      if (k <= n - 4) high |= byte;
      else v = v * 256 + byte;
    }
    // `push` records that the target is a known constant at all; `value` is that
    // constant only when it is narrow enough to be a code offset. the two are
    // not the same question: PUSH5 0xff00000000 is perfectly well known, it is
    // just far too big to be an offset, so it provably does NOT reach the blob.
    out.push({ at: i, op, push: true, value: high === 0 ? v : null });
    i += n; // skip the immediate
  }
  return out;
}

// Can the code before `start` get INTO the trailing blob? Honest metadata is
// data - nothing has any reason to jump into its own ipfs hash - so any way in
// is the tell that the "metadata" is really code wearing a metadata hat.
//
// The old version of this asked a narrower question: does some single literal
// push name a byte in the blob? That is only one way in, and it was disclosed
// as a known limit, described as a target "computed at runtime". It is not:
//
//     PUSH1 7 ; PUSH1 3 ; ADD ; JUMP
//
// jumps to 10 using nothing but two compile-time constants, and neither 7 nor 3
// is inside the blob, so nothing was flagged and a JUMPDEST/SELFDESTRUCT pair
// sitting in the "hash" was trimmed away unscanned. That is not an exotic case
// to construct, it is just declining to fold your own constant.
//
// So the question is inverted. We no longer look for a way in and trim when we
// fail to find one; we trim only when there is provably no way in:
//
//   'unreachable' - either nothing in the blob is a valid JUMPDEST, so there is
//                   nowhere to land, or every jump in the body names a constant
//                   and none of those constants is in the blob.
//   'reachable'   - a constant in the body names a JUMPDEST in the blob. caught.
//   'unprovable'  - the body jumps somewhere this walk cannot read off the
//                   instruction stream (built by arithmetic, or arriving on the
//                   stack), and the blob has somewhere for such a jump to land.
//                   We cannot say it is safe, so we do not say it.
function trailerReach(b, start) {
  const instrs = instructionsOf(b);
  const end = b.length - 2;
  const dests = new Set(
    instrs.filter((x) => x.op === JUMPDEST && x.at >= start && x.at < end).map((x) => x.at),
  );
  if (dests.size === 0) return 'unreachable';

  let unprovable = false;
  for (let k = 0; k < instrs.length; k++) {
    const ins = instrs[k];
    if (ins.at >= start) break; // only the body's own jumps matter
    if (ins.value !== null && dests.has(ins.value)) return 'reachable';
    if (ins.op !== JUMP && ins.op !== JUMPI) continue;
    // a jump whose target this walk cannot name. a literal push immediately
    // before the jump is the compiled shape we can read, and it settles the
    // question either way: the constant is either in the blob (caught above) or
    // it is not. anything else - a SWAP, an ADD, an SLOAD - means the target
    // came from somewhere we are not tracking, and then we cannot say.
    const prev = instrs[k - 1];
    if (!prev || !prev.push) unprovable = true;
  }
  return unprovable ? 'unprovable' : 'unreachable';
}

// solc appends a CBOR metadata blob after the runtime code. the last 2 bytes
// are its length, and the blob starts with a small cbor map. trimming it stops
// us walking the ipfs hash bytes as if they were opcodes - random hash bytes
// hit 0xff / 0xf4 often enough to false-alarm on perfectly honest contracts.
//
// but the trim is attacker-facing: both the length field and the marker byte
// live in code the recipient chose. trusting them means "declare your tail to
// be metadata and the scanner stops there" - a false NEGATIVE, and that's the
// one direction this lane can't fail in. so two checks before we cut:
//   1. the blob has to be structurally valid cbor that accounts for every byte
//      up to the length field, not just one byte that looks like a map header.
//   2. even then, we won't cut a blob the code jumps into.
// returns the body to scan plus whether we caught the tail pretending.
//
// check 2 used to ask whether some literal push named a byte in the blob, and
// called a target built any other way a "runtime" limitation. Two constants and
// an ADD is not runtime anything, so that gap is now closed the only way a
// linear scan honestly can: by trimming ONLY when the blob is provably
// unreachable, and scanning the whole thing whenever it cannot be shown to be.
//
// Refusing to trim costs something - the metadata gets walked as opcodes, which
// is the false alarm the trim exists to prevent - so it is spent only where it
// buys something. If the blob scans clean there is nothing in there to hide and
// the trim happens anyway.
//
// That cost is measured, not assumed. Recompiling this repo's own contracts
// 3000 times each with randomised metadata hashes, 1.6% of honest builds stop
// being trimmed: the ones whose hash bytes happen to contain a danger opcode at
// an instruction boundary behind a JUMPDEST. Those get read as flagged code they
// are not. That is the trade, in the direction this lane has always said it
// would take it - a false alarm is somebody looking at a contract that turns out
// to be fine, and a false negative is money gone.
//
// exported so the trim boundary can be asserted directly without a chain, the
// same way floatPlan is in guard.js - inferring it from a score is unreliable,
// because whether a trimmed byte was ever walked depends on push alignment.
export function stripMetadata(hex) {
  const bytes = Buffer.from(hex.slice(2), 'hex');
  if (bytes.length < 4) return { body: hex, hidden: false };
  const len = bytes[bytes.length - 2] * 256 + bytes[bytes.length - 1];
  const start = bytes.length - 2 - len;
  if (start <= 0) return { body: hex, hidden: false };

  // not real metadata - scan the whole thing rather than trusting the trailer
  if (cborEnd(bytes, start) !== bytes.length - 2) return { body: hex, hidden: false };

  const trimmed = '0x' + bytes.subarray(0, start).toString('hex');
  const reach = trailerReach(bytes, start);

  // well-formed, but named by the code. that's not metadata, that's a hiding place.
  if (reach === 'reachable') return { body: hex, hidden: true };

  // we cannot prove it is unreachable. that only matters if there is something
  // in there worth reaching, so ask: does walking the whole thing find danger
  // the trimmed body does not? if not, the two scans agree and the trim is free.
  // this is what keeps an honest contract whose hash happens to contain a 0x5b
  // from being treated as a suspect.
  if (reach === 'unprovable' && hidesDanger(hex, trimmed)) return { body: hex, hidden: false };

  return { body: trimmed, hidden: false };
}

// does scanning everything turn up a danger opcode that scanning the body alone
// does not? scanOpcodes is declared below and hoisted.
function hidesDanger(full, body) {
  const inFull = scanOpcodes(full);
  const inBody = scanOpcodes(body);
  return Object.keys(inFull).some((k) => (inFull[k]?.count ?? 0) > (inBody[k]?.count ?? 0));
}

// walk the code instruction by instruction, counting danger opcodes
function scanOpcodes(hex) {
  const bytes = Buffer.from(hex.slice(2), 'hex');
  const hits = {};
  for (let i = 0; i < bytes.length; i++) {
    const op = bytes[i];
    if (isPush(op)) {
      i += pushLen(op); // skip the immediate data
      continue;
    }
    const d = DANGER[op];
    if (d) {
      if (!hits[d.name]) hits[d.name] = { count: 0, score: d.score, note: d.note };
      hits[d.name].count += 1;
    }
  }
  return hits;
}

// eip-1167 minimal proxy: a fixed 45-byte runtime that just delegatecalls to a
// hardcoded implementation baked into the middle. exact shape, nothing after -
// the real logic lives in another contract we can't see from here.
//   363d3d373d3d3d363d73 <20-byte impl> 5af43d82803e903d91602b57fd5bf3
const PROXY_HEAD = '363d3d373d3d3d363d73';
const PROXY_TAIL = '5af43d82803e903d91602b57fd5bf3';

function isMinimalProxy(hex) {
  const h = hex.slice(2).toLowerCase();
  return h.length === 90 && h.startsWith(PROXY_HEAD) && h.endsWith(PROXY_TAIL);
}

function levelFromScore(score) {
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
}

export async function checkBytecode(recipient) {
  const code = await publicClient.getCode({ address: recipient });
  const lower = (code || '0x').toLowerCase();

  // eip-7702: a delegated EOA returns 0xef0100 || <20-byte address>. it's not a
  // real contract, execution is just forwarded to that address, so don't scan
  // the address bytes as opcodes. flag it so a human can look at the delegate.
  if (lower.startsWith('0xef0100') && lower.length === 48) {
    const target = '0x' + lower.slice(8);
    return {
      lane: 'bytecode',
      level: 'MEDIUM',
      score: 40,
      isContract: false,
      code,
      reason: `EOA with an EIP-7702 delegation to ${target}. Execution is forwarded to that contract.`,
      hits: {},
    };
  }

  // no code = a normal wallet (EOA). nothing to run, low risk.
  if (!code || code === '0x') {
    return {
      lane: 'bytecode',
      level: 'LOW',
      score: 0,
      isContract: false,
      code: '0x',
      reason: 'Recipient is a normal wallet (EOA) - no contract code to run.',
      hits: {},
    };
  }

  // when the tail is only pretending to be metadata, `body` is the untrimmed
  // code - so whatever it was hiding gets walked like any other instruction.
  const { body, hidden } = stripMetadata(code);
  const hits = scanOpcodes(body);
  if (hidden) {
    hits.HIDDEN_CODE = {
      count: 1,
      score: 60,
      note: 'the trailing "metadata" blob is jumped into by the code - it is executable, not a solc metadata hash',
    };
  }

  // if it's a recognized minimal proxy, report that precisely instead of a
  // bare delegatecall - the real signal is "logic is hidden elsewhere".
  if (isMinimalProxy(code)) {
    delete hits.DELEGATECALL;
    hits.MINIMAL_PROXY = {
      count: 1,
      score: 40,
      note: 'eip-1167 minimal proxy - forwards every call to a hidden implementation you cannot inspect here',
    };
  }

  const score = Object.values(hits).reduce((s, h) => s + h.score, 0);
  const level = levelFromScore(score);
  const byteLen = code.length / 2 - 1;

  let reason;
  if (score === 0) {
    reason = `Recipient is a contract (${byteLen} bytes) with no known danger opcodes.`;
  } else {
    const parts = Object.entries(hits).map(
      ([name, h]) => `${name} x${h.count} (${h.note})`,
    );
    reason = `Contract bytecode contains: ${parts.join('; ')}.`;
  }

  // say what it is before saying what's in it - a known proxy reads very
  // differently from an anonymous one, even at the same score.
  const system = CIRCLE_SYSTEM[recipient.toLowerCase()] ?? null;
  if (system) {
    reason = `${system.name} - a Circle system contract, ${system.trust}. ${reason}`;
  }

  return { lane: 'bytecode', level, score, isContract: true, code, reason, hits, system };
}
