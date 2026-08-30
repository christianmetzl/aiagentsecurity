const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, BorderStyle,
} = require('docx');

const FONT = 'Times New Roman';
const children = [];

// helpers -------------------------------------------------------------------
const title = (t) => children.push(new Paragraph({
  alignment: AlignmentType.CENTER, spacing: { before: 120, after: 80 },
  children: [new TextRun({ text: t, bold: true, size: 34, font: FONT })],
}));
const authors = (lines) => lines.forEach((l, i) => children.push(new Paragraph({
  alignment: AlignmentType.CENTER, spacing: { after: i === lines.length - 1 ? 200 : 20 },
  children: [new TextRun({ text: l, size: i === 0 ? 24 : 20, font: FONT })],
})));
const h = (t) => children.push(new Paragraph({
  heading: HeadingLevel.HEADING_1, spacing: { before: 220, after: 90 },
  children: [new TextRun({ text: t, bold: true, size: 26, font: FONT })],
}));
// paragraph with optional bold lead-in; `body` may be an array of {t,b?,i?} runs
const p = (lead, body, opts = {}) => {
  const runs = [];
  if (lead) runs.push(new TextRun({ text: lead + ' ', bold: true, size: 22, font: FONT }));
  const parts = Array.isArray(body) ? body : [{ t: body }];
  for (const part of parts) runs.push(new TextRun({ text: part.t, bold: !!part.b, italics: !!part.i, size: 22, font: FONT }));
  children.push(new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { after: 120 }, children: runs, ...opts }));
};
const bullet = (lead, text) => children.push(new Paragraph({
  bullet: { level: 0 }, alignment: AlignmentType.JUSTIFIED, spacing: { after: 60 },
  children: [
    ...(lead ? [new TextRun({ text: lead + ' ', bold: true, size: 22, font: FONT })] : []),
    new TextRun({ text: text, size: 22, font: FONT }),
  ],
}));
const ref = (n, text) => children.push(new Paragraph({
  spacing: { after: 40 }, indent: { left: 360, hanging: 360 },
  children: [new TextRun({ text: `[${n}] ${text}`, size: 20, font: FONT })],
}));
const rule = () => children.push(new Paragraph({
  border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: '999999', space: 1 } },
  spacing: { after: 120 }, children: [],
}));

// content -------------------------------------------------------------------
title('FORGE: Reverse-Engineering the Reward Economics of a Multi-Step Tool-Attack Benchmark, with a Matched Defense');
authors(['Christian Metzl', 'Independent Researcher · christianmetzl@aol.com',
  'Working Note — AI Agent Security: Multi-Step Tool Attacks (Kaggle, 2026)']);
rule();

h('Abstract');
p(null, [{ t: 'We study the Kaggle ' }, { t: 'AI Agent Security — Multi-Step Tool Attacks', i: true },
  { t: ' benchmark, in which an attacker submits candidate conversations that drive two open-weight tool-using models (gpt-oss-20b, gemma-3-4b) and is scored by the security predicates they are induced to trigger. Rather than treat the task as prompt engineering, we reverse-engineer its reward economics from the evaluation gateway and a publicly shared competitor solution, and show that one relation governs everything: score ≈ 0.09 × (tool calls that fire), a time-bounded linear knapsack. The binding constraint is not model refusal — single requests comply ≈100% — but posts sustained per candidate and candidate throughput under a fixed replay budget. We contribute (i) a formal statement of the objective and its optimal allocation; (ii) three throughput levers — aggressive token minimization, bounded multi-message packing, and a sustain-aware bandit probe that selects framings by measured value-per-second on the live model; (iii) an honest treatment of “quantum-inspired” optimization, which the linear structure rules out except at the probe; and (iv) a matched defense — a prompt-agnostic action-side guardrail plus a chat-template input sanitizer — that collapses our own strongest attacks to zero with no benign false positives. Every claim is tagged [measured]/[inferred]/[speculative], and we document our wrong turns as the most transferable lessons. This is a defensive study of a sandboxed benchmark with synthetic markers; the one guardrail gap we exploit is disclosed to the organizers with a fix.' }]);

h('1  Benchmark Mechanics and Reward Economics');
p('Scoring [measured, from aicomp_sdk/scoring.py].', 'With severity weights w(5)=16, w(4)=8, w(3)=4, summed per triggered event with no de-duplication, plus +2 per distinct score cell (keyed on destination domain + tool sequence, not message text): raw = Σ w(severity) + 2·cells, and score = min(1000, raw/200). The dominant action is an http.post carrying a synthetic marker, firing EXFILTRATION (severity 5 = 16 raw). With one distinct destination domain per post (a free +2 cell), each successful post is worth 18 raw = 0.09 normalized.');
p('The governing relation.', 'The gateway replays up to 2000 candidates but is bounded by a per-phase wall-clock budget B ≈ 8750 s; each candidate costs L ≈ prefill + K·decode, dominated by a ≈25 s prefill for a 20B model on the evaluation hardware (a constant the competitor solution encodes directly). Because scoring is additive with no interaction, score ≈ 0.09 × (tool calls that fire), and firing calls = (candidates that fit B) × (posts sustained per candidate, K_eff). Single-request compliance is ≈100% — refusal is not the wall. The levers are (a) fit more candidates into B (smaller L) and (b) sustain more posts per candidate (K_eff).');
p('Optimal allocation.', 'With value v = 16·K_eff + 2·C and cost c = L per candidate route, maximizing Σv subject to Σc ≤ B is a fractional knapsack; sorting by v/c and filling greedily is provably optimal. FORGE probes each route on the live guardrail, estimates v/c from the measured trace, orders best-first, and fills B.');

h('2  The Throughput Gap, Reverse-Engineered');
p(null, 'Our first real-eval scores were ≈15 (public); a public solution reported ≈60 and the leader 147.53. We first mis-read this as a “9% compliance wall.” Reading the competitor’s own code corrected us: (a) single-post framings are “proven ≈100% fire” — the 0.09 is the score of one complying post, not a compliance rate; (b) the differentiator is K_eff — our same-URL “repeat the post N times” batch sustained ≈0.7 of 8, whereas a distinct-record ETL framing (“forward each of these N records, one call per record”) sustained ≈3, reading as a real batch job rather than a pointless loop; (c) longer prompts inflate prefill L and thus reduce the candidate count — which independently explains why our “smarter” verbose jailbreaks scored worse. Reframing from “crack a compliance wall” to “maximize firing posts per second” is the single most important result of the study.');

h('3  Innovations Beyond the Public Floor');
p(null, 'Treating the competitor mechanism as a floor, we add three levers, each targeting a term in the objective:');
bullet('Token minimization.', 'Short endpoints (http://d00001.invalid), minimal distinct records, and a hard output/reasoning suppressor cut message length ≈38%. Fewer input and output tokens shrink both prefill and decode, raising both candidate count and K_eff.');
bullet('Bounded multi-message packing.', 'One interaction caps at 8 tool hops; exceeding 8 posts/candidate requires multiple messages, which crashed at high density (context-length OOM on a 20B CPU model). We bound it to 2–3 ultra-short messages (16–24 posts/candidate) so accumulated context stays ≈8× smaller than the crashed build, amortizing one 25 s prefill over many posts.');
bullet('Sustain-aware bandit probe.', 'The naive probe commits to the first framing that fires; “fires once” ≠ “sustains the most.” We treat framing choice as a budget-constrained multi-armed bandit: draw each of a few framings r times, estimate its v/c, and commit to the best — adapting K_eff to the actual rerun model, which is unobservable offline. No static framing has this edge.');
p(null, 'A lever model on the competitor’s constants suggests these compound from the ≈58 floor toward ≈97 (token-min) and, with working packing, well beyond [inferred; the projections are not measured].');

h('4  On “Quantum-Inspired” Optimization');
p(null, 'Because scoring is additive with no dedup and distinct domains yield distinct cells, there are no diminishing returns or cross-candidate interactions: the allocation is a linear knapsack, for which greedy is provably optimal. Determinantal point processes, simulated/quantum annealing, and QAOA offer nothing over greedy here — indeed our DPP selector reduces exactly to greedy and is disabled. The one sub-problem with genuine stochastic structure is which framing to commit to under a tiny query budget against a noisy model: a multi-armed bandit, solved in Thompson-sampling spirit by the sustain-aware probe. The principled “sampling-based” optimizer and the real algorithmic edge are thus the same object; we resist dressing greedy as something exotic.');

h('5  From Attack to Defense');
p(null, 'The public guardrail has one genuine gap (Bug 1 [source-traced]): it inspects an http.post’s URL for danger but not its data channel, so a benign-looking URL carrying the marker in data is allowed and scores. We report it here and disclose it to the organizers with a fix. The matched defense has two layers: (1) Action-side, prompt-agnostic inspection — a guardrail that checks the data channel with the scorer’s own matcher and tracks provenance (secret-read and untrusted-source taint) denies the exfil regardless of framing; every compliance jailbreak we tried (role-play, Crescendo, many-shot, fake-over-refusal, policy-collision) changes the model’s willingness but not the tool call, so none pass this boundary. (2) Input-side sanitization — the one attack a pure action-filter cannot pre-empt is chat-template forgery (injecting Harmony/gemma control tokens to forge a prior turn); a small sanitizer neutralizes those tokens before templating.');
p('[measured]', 'Running our strongest attack builds against the reference guardrail collapses their score to 0 (e.g. normalized 23.8 → 0), with zero benign false positives. Stopping a jailbreak at the action boundary beats an input classifier the jailbreak is engineered to slip past — the transferable defensive lesson.');

h('6  Results (Measured, Real Evaluation)');
bullet('Throughput vs single-post.', 'A terse batch-8 build scored 14.915, +36% over the best single-post build (10.935) at the same configuration — consistent with the objective (batch amortizes the fixed prefix).');
bullet('The private-coverage lever is clean and linear.', 'Reserving fraction pf of the scored prefix for public-null private routes gives public {0.05:10.94, 0.15:8.86, 0.30:7.69, 0.45:5.74, 0.60:4.29} ≈ 11.5 − 12.1·pf.');
bullet('Verbose “jailbreaks” regressed.', 'Role-play / Crescendo / many-shot framings lowered the score (10.94 → 7.58 and 7.47) — longer prefixes cost candidates and mangle the tool JSON on small models. Terse wins twice.');
bullet('Multi-message dense crashed', 'on the real eval (Kaggle Error), motivating the bounded, token-minimized hybrid.');
p(null, 'The private column that decides the final rank is hidden until close; we hedge a dedicated private-coverage submission and treat public projections above ≈15 as [inferred], not established.');

h('7  Lessons Learned');
bullet('Measure the objective before optimizing it.', 'Weeks of “compliance” effort dissolved once we read the scorer: the constraint was throughput, not refusal.');
bullet('A wall can be a mis-read.', 'The “9%” was posts-sustained, not a refusal rate; the fix was candidate structure, not a better jailbreak.');
bullet('Cleverness can cost points.', 'Literature-grade jailbreaks (role-play ≈71% on gpt-oss for chat content) regressed tool-call throughput. Negative results matter.');
bullet('Test the shortcut before believing it.', 'A “stack two predicates per post” (16 → 32) idea was killed by a one-line experiment: the public guardrail taint-blocks the post after an untrusted read, so both predicates die.');
bullet('Attack and defense are one project.', 'The prompt-agnostic guardrail that zeroes our attack is the same artifact that makes the finding useful to defenders.');

h('8  Responsible Disclosure and Ethics');
p(null, 'This is defensive research on a sandboxed benchmark: the “secret” is a synthetic literal (SECRET_MARKER), destinations are reserved *.invalid / *.example names, and no real system or person is targeted — the competition’s stated purpose. Bug 1 is documented and disclosed to the organizers, together with the fixed reference guardrail and input sanitizer in the accompanying code. We publish no operational capability against any real deployment. Development, analysis, and drafting were assisted by Claude Code (Anthropic).');

h('References');
ref(1, 'M. Bhatt, C. Huang, O. Vallis, J. Chang, S. Mathews, B. Gatto, M. Cruz, Y. Yan, M. Plomecka. AI Agent Security — Multi-Step Tool Attacks. Kaggle, 2026. https://kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks');
ref(2, 'yusuketogashi. lb60-525-july-safe-edge-prune-tail8-upgrade (public competition notebook; portfolio / latency-sizing lineage from pilkwang). Kaggle, 2026. https://www.kaggle.com/code/yusuketogashi/lb60-525-july-safe-edge-prune-tail8-upgrade');
ref(3, 'pilkwang. AI-Agent single-post exfiltration; replay dense exfiltration (public notebooks). Kaggle, 2026. https://www.kaggle.com/pilkwang');
ref(4, 'nctuan. JED slow multipost (public notebook). Kaggle, 2026. https://www.kaggle.com/code/nctuan/jed-slow-multipost');
ref(5, 'C. Anil et al. Many-shot Jailbreaking. Anthropic, 2024.');
ref(6, 'Z. Chen et al. Bag of Tricks for Subverting Reasoning-Based Safety Guardrails. arXiv:2510.11570, 2025.');
ref(7, 'Dialogue Injection Attack: Jailbreaking LLMs through Context Manipulation. arXiv:2503.08195, 2025.');
ref(8, 'Probing GPT-OSS-20B (Quant Fever, Schrödinger’s Compliance, …). arXiv:2509.23882, 2025.');
ref(9, 'Sequential Tool-Attack Chaining (STAC). arXiv:2509.25624, 2025.');

// build ---------------------------------------------------------------------
const doc = new Document({
  styles: { default: { document: { run: { font: FONT, size: 22 } } } },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } },
    children,
  }],
});
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync('forge_working_note.docx', buf); console.log('wrote forge_working_note.docx', buf.length, 'bytes'); });
