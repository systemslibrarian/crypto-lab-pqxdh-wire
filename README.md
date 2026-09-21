# PQXDH Wire

## What It Is

PQXDH Wire is an interactive, browser-only walkthrough of Signal's PQXDH Revision 3 key agreement. It runs four X25519 agreements, strict Ed25519 prekey signatures, ML-KEM-1024, HKDF-SHA-512, and AES-256-GCM with real cryptographic implementations. Alice and Bob derive the session key in separate modules and compare all 32 bytes.

The lab teaches one boundary: adding an independent post-quantum KEM secret to the X3DH transcript prevents a modeled future curve break from recovering the initial session key. The curve and lattice breaks are explicitly modeled by handing private values to an adversary module; no quantum algorithm runs in the browser.

This is not production cryptography. It uses Ed25519 instead of XEdDSA and standardized FIPS 203 ML-KEM-1024 instead of Revision 3's example CRYSTALS-KYBER-1024. Kyber round 3 and ML-KEM are not wire-compatible. Keys remain in memory and are discarded on reload or reset.

## Exhibits

1. **Build the transcript** — publish Bob's signed bundle, derive Alice's four DH outputs and KEM secret, send the initial message, derive independently as Bob, and compare the session keys.
2. **Open the boxes** — grant a model every X25519 private key, then separately grant the ML-KEM shared secret and watch the adversary recompute only when all inputs exist.
3. **Break real checks** — corrupt the signed ML-KEM prekey and flip a ciphertext bit against the actual Ed25519, ML-KEM, and AES-GCM paths.
4. **Reuse the fallback** — exhaust one-time PQ prekeys and watch the page measure three facts before it says anything: that the served key really is the last-resort key, that both sessions cite one PQ prekey id, and that the per-session KEM secrets still differ. It does not claim reuse alone reveals either session key.
5. **Forge authentication** — grant an active model Bob's classical signing and curve identity secrets; every check passes while Alice talks to the adversary.
6. **Follow the ratchet** — run a reduced three-step X25519 root-key model. The adversary keeps its own root chain, advanced only from the public transcript plus whatever the model grants it, so `HEALED` and `HEALED — AND STILL READ` are a comparison of two chains rather than a restatement of the premise.
7. **Diff X3DH and PQXDH** — inspect the exact 32-byte KDF addition and 1,568-byte initial-message addition.

## When to Use It

Use this lab to learn the boundary between PQXDH's post-quantum initial-key confidentiality and its classical authentication, to inspect Revision 3's transcript ordering, or to test how implicit rejection surfaces at the first AEAD.

Do not use this code as a messaging protocol, a libsignal-compatible implementation, a Double Ratchet implementation, or evidence that a real quantum computer has broken X25519 or ML-KEM. Production systems need reviewed protocol state, serialization, erasure, side-channel controls, prekey-server behavior, replay handling, and a production cryptographic backend.

## Live Demo

[Open PQXDH Wire on GitHub Pages](https://systemslibrarian.github.io/crypto-lab-pqxdh-wire/).

Complete the five handshake steps, inspect every KDF input, enable each adversary capability, then run the signature, KEM-ciphertext, prekey-reuse, impersonation, and ratchet fixtures.

Every outcome the page renders carries a `data-verdict` marker and every number it renders carries a `data-claim` marker, and every marker of either kind is killed by a recorded mutation (below). No verdict and no measurement on this page is a constant.

## What Can Go Wrong

- A bad signed prekey must abort Alice before key agreement.
- A modified ML-KEM ciphertext produces a pseudorandom rejected secret; the mismatch appears at AES-GCM authentication, not as a decapsulation error.
- Reusing the signed last-resort PQ prekey widens the impact of a later private-key compromise compared with deleting a one-time key.
- PQXDH authentication is not quantum-secure. An active quantum adversary that forges the classical identity signature can impersonate Bob while all checks pass.
- A classical X25519 Double Ratchet step provides classical post-compromise healing, not post-quantum healing. Signal's SPQR and Triple Ratchet address that later phase.
- Omitting `F`, changing the DH order, or failing to bind the KEM public key in associated data changes the protocol transcript.

## Real-World Usage

Signal introduced PQXDH to resist harvest-now-decrypt-later attacks against asynchronous session setup. This lab pins the public specification at Revision 3, dated 2023-05-24 and last updated 2024-01-23. Signal's implementation uses a Kyber-1024 profile; this browser lab deliberately uses the standardized, non-wire-compatible ML-KEM-1024 primitive and labels that deviation throughout.

Signal announced SPQR and the Triple Ratchet on 2025-10-02 to add post-quantum forward secrecy and post-compromise security after session setup.

## How to Run Locally

Requires Node.js 22 or newer.

```bash
npm ci
npm run dev
```

Vite prints the local URL. To run every gate exactly as CI does:

```bash
npm run test:coverage
npm run build
npx playwright install --with-deps chromium
npm run test:a11y
```

To see a verdict fail, apply one of the recorded mutations and rerun. `CI=1` is
required: it turns off Playwright's `reuseExistingServer`, so the suite cannot
hit a stale server built from unmutated code and report a survivor.

```bash
npm run mutate list
npm run mutate apply ratchet-grant-is-not-a-recovery
CI=1 npm run test:verdicts     # ratchet-heal must fail on its own assertion
npm run mutate revert ratchet-grant-is-not-a-recovery
```

## Related Demos

- [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) — the full browser-demo catalog.
- [Signal X3DH specification](https://signal.org/docs/specifications/x3dh/) — the classical handshake PQXDH extends.
- [Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/) — the post-handshake ratchet modeled here only at one reduced boundary.
- [Signal Protocol and Post-Quantum Ratchets](https://signal.org/blog/spqr/) — where SPQR and the Triple Ratchet take the story next.

## Build & Verify

The repository has **49 executable tests**: 22 Vitest unit/correctness tests and 27 Playwright tests (2 accessibility, 8 claims, 12 per-marker, 5 verdict-coverage).

V8 coverage over the cryptographic, protocol, model, and verification modules is 94.77% statements, 93.24% branches, 90.32% functions, and 95.04% lines. CI enforces floors of 90% statements, 85% branches, 85% functions, and 90% lines.

Three specification known-answer tests are pinned in source:

- RFC 7748 X25519 test vector.
- RFC 5869 HKDF test case 1.
- NIST ACVP FIPS 203 ML-KEM-1024 keyGen `tgId 3 / tcId 51`, checked against digests of the complete 1,568-byte encapsulation key and 3,168-byte decapsulation key.

The remaining correctness tests cover independent Alice/Bob derivation, exact `F || DH1 || DH2 || DH3 || DH4 || SS` ordering, signature failure, curve-prekey exhaustion, last-resort fallback, ML-KEM implicit rejection, adversary input isolation, classical impersonation, and reduced-ratchet outcomes. No stable byte-for-byte libsignal PQXDH transcript vector was found in the public repository search on 2026-09-11; the lab states that limit instead of presenting component tests as an end-to-end interoperability vector.

The Playwright gate builds before serving, drives every real UI state at desktop and 380 px, runs Axe WCAG 2.1 A/AA, asserts Axe's incomplete bucket, measures text and non-text contrast, checks reflow and keyboard-reachable scrollers, independently recomputes HKDF with Node's `crypto`, and exercises both negative claims.

### Verdict coverage

Reading the code is not evidence that a rendered outcome is real. Three of this
fleet's eight audited labs shipped a verdict that could not come out the other
way, and none was caught by reading. This lab's own `checksGreen` was a literal
until a66045f, and an auditor then found `stillReadable` in
`src/model/ratchet-step.ts` true by construction for the same reason.

So coverage here is derived from the rendered page, never from a list written by
hand:

- Every element that renders an outcome carries `data-verdict="<id>"`. There are
  eleven: `handshake-status`, `session-key-match`, `session-key-state`,
  `kdf-input-state`, `adversary-model`, `prekey-signature-abort`,
  `kem-tamper-abort`, `last-resort-reuse`, `impersonation`, `ratchet-heal`,
  `wire-secrecy`.
- Every element that renders a measurement carries `data-claim="<id>"`, with the
  machine value in `data-value`. There are four: `wire-kem-ct-bytes`,
  `wire-ad-bytes`, `wire-scanned-secret-bytes`, `wire-secret-bytes`. A rendered
  number is a claim in exactly the way a rendered word is, and it is the easier
  one to leave unchecked, because a number does not look like a claim. Three of
  them were `1,568 B`, `1,632 B` and `0 B` written into the page template until
  this pass — and `0 B`, the strongest claim the exhibit makes, was a literal
  about nothing. `wire-scanned-secret-bytes` is new: a search reporting "found
  none" is evidence only if the page also says how much it looked for.
- `e2e/verdicts.spec.ts` asserts what each marker renders **and the state it
  paints**, together, through `expectVerdict` / `expectClaim`. The helper
  refuses a text-only claim: a mutation that flips the words while leaving
  `data-result="pass"` in place would otherwise be recorded as a kill, and the
  marker would go on claiming pass in every way a reader can see except the
  sentence.
- `e2e/verdict-mutations.json` records the mutations that kill them — a
  single-token edit to real source that forces the measured value the other way.
- `e2e/drive-every-state.ts` is the denominator, not a test. It visits every
  option of every control that changes what renders — each control on its own,
  not the full cross-product — because a marker that appears only in a state the
  walk never reaches is outside the set the coverage rules judge. The table in
  that file lists every control and what it owes, and names the three controls
  deliberately skipped with the reason.
- `e2e/verdict-coverage.spec.ts` enumerates over that walk and fails on a
  rendered marker of **either** family that no mutation covers, on a mutation
  naming a marker the page never renders, on a covered id that no
  `expectVerdict` / `expectClaim` call asserts, on a mutation whose `find` no
  longer matches its file, and on any verdict word, verdict styling **or
  digit-plus-unit measurement** rendered outside a marker in a result region.
  Its fourth test injects both a raw unmarked banner and a raw unmarked number
  the way a careless builder would, and fails if the scanner stays quiet.

A kill counts only when the unmutated baseline passed in the same run, the
failure is that verdict's own assertion rather than a build error or a blank
page, and the server served the mutated code. All eleven recorded mutations were
run that way, with `CI=1`; each failed the markers it claims to cover, on those
markers' own assertions, and no other per-marker test. Several also turn the
coverage walk red, which is expected rather than collateral damage: the walk
asserts the intermediate states it steps through, and `every recorded mutation
still applies to the source it names` necessarily fails while a mutation is
applied, because the `find` string it looks for is the line the mutation just
replaced.

`verdict-gate` is a separate job so it is a separate check, and `deploy` and
`dependabot-auto-merge` both list it in `needs:`. `main` here carries no branch
protection, so it is not a *required* status check — `needs:` is what actually
holds, and it covers a direct push to `main`, which skips pull-request checks
entirely. Whether protection spreads beyond this fleet's three pilot labs is the
maintainer's call and is deliberately not changed from inside this lane. CI
blocks deployment unless every check passes.

Primary sources: [PQXDH Revision 3](https://signal.org/docs/specifications/pqxdh/), [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), and [Bhargavan et al., USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan).

## Performance

All operations run on the main browser thread for inspectability. A handshake performs four X25519 agreements per party, one ML-KEM-1024 encapsulation and decapsulation, two HKDF derivations, and one AES-GCM round trip. This is intentionally a single-session teaching workload, not a throughput benchmark; JavaScript timing is not constant-time and must not be treated as side-channel evidence.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*