# PQXDH Wire — build brief for `crypto-lab-pqxdh-wire`

Save this file as `brief.md` at the root of `crypto-lab-pqxdh-wire`. The binding spec is the copy of `_MASTER-TEMPLATE.md` in this repo (status 2026-08-02); this brief supplies only the demo-specific facts. Where the two touch, the template wins; where the template and the catalog `CLAUDE.md` touch, `CLAUDE.md` wins. If `audits/kickoff.md` is also present in this repo, it may be used instead of the prompt below — it reads `./brief.md` itself.

## Kickoff prompt — paste this, with the template in the repo

```text
Build a new Crypto Lab browser demo (Vite + TypeScript, static site, no backend).

Read _MASTER-TEMPLATE.md (copied into this repo — check audits/ and the repo root) in
full and treat it as the BINDING spec. Build to every standard in it, in this order:

  1. §1 Build — real crypto only (WebCrypto or a named, justified library; hand-roll
     the inspectable teaching parts; NEVER simulate or fake math). Runnable tests that
     actually pass, including spec KATs (state the count). Mount content at id="app";
     define --accent on :root.
  2. §3 Look — add the standard top bar (copy the header from any existing lab and
     adapt it) and the standardized hero (short-name <h1> + spec subtitle + "Why it
     matters" box beside it; title size capped at clamp(1.6rem,3.8vw,2.7rem)); theme
     contract; scripture footer; head/favicon. Do NOT invent a new header design and do
     NOT add a theme toggle — match the fleet's cl-topbar.
  3. §2 Teach — SHOW the one headline mechanism (animate/step it, never assert it in
     prose or raw hex); add a plain-language "what is this / why it matters" intro and a
     break-it-yourself interaction against the real crypto; no decorative/idle animation;
     pitch to a college newcomer while rewarding an expert (progressive disclosure).
  4. §4 Accessibility — wire the WCAG 2.1 AA gate and author to its checklist.
     `npm run build` then `npm run test:a11y` MUST pass with zero violations.
  5. §5 README (the standard sections) and §6 Deploy (Actions-based Pages, a11y-gated).
  6. §6.1 + §6.2 Dependency automation — REQUIRED, not optional. Ship
     .github/dependabot.yml with the grouped config, add the dependabot-auto-merge job
     to whichever workflow runs the gate on pull_request, and have that job dispatch the
     deploy after it merges. Also: the workflow must trigger on pull_request as well as
     push, the deploy job must be gated to `github.event_name != 'pull_request'`, the concurrency
     group must include ${{ github.ref }}, and the deploy workflow must accept
     workflow_dispatch. Omitting any of these is how a lab starts opening one pull request
     per dependency with no CI signal on any of them.

Hard rules: do NOT dumb down the crypto to make a visual simpler; honest scoping in-page
and in the README ("not production", what's real vs simulated, what it does NOT prove).
Do NOT weaken a gate to get a green run — no skipped tests, no lowered coverage threshold,
no disabled lint rule, no re-recorded a11y baseline, no continue-on-error. If a bump or a
change cannot pass honestly, leave it failing and say so.
When done, report a one-line summary with the test count, and confirm all four of
grouping / auto-merge / PR gate / workflow_dispatch are present.

The rest of ./brief.md — the §1 sections, hero copy, claims suite, negative claim,
pre-build verification and citations below the DEMO BRIEF — is part of this brief.
Read it in full before building; run its pre-build checks first and report them.

DEMO BRIEF:
NEW DEMO BRIEF
- Repo name:         crypto-lab-pqxdh-wire
- Short name (H1):   PQXDH Wire
- Subtitle:          Post-quantum asynchronous handshake · Signal PQXDH · revision <pinned at build>
- One-liner:         Runs Signal's PQXDH — X3DH's four X25519 agreements plus one ML-KEM encapsulation against a signed post-quantum prekey, into one HKDF — with real X25519, signatures, ML-KEM and HKDF-SHA-512, then gives the adversary a quantum computer and shows which boxes that opens and which it does not.
- Concept to teach:  One KEM secret added to the KDF input is what makes the initial key harvest-proof. The signature that authenticates the prekeys, and the Double Ratchet's later healing, are still classical — which is why the next protocol exists.
- Primitives/spec:   The PQXDH Key Agreement Protocol (Kret & Schmidt; three revisions to date per the spec's revision history — confirm the current revision and its date at signal.org/docs/specifications/pqxdh at build and cite it); the X3DH specification (Marlinspike & Perrin, 2016) for the diff; FIPS 203 ML-KEM via a named library with its KATs; RFC 7748 X25519 with vectors; RFC 5869 HKDF with vectors; SHA-512. Signatures over the prekeys: XEdDSA if X3DH Wire already carries it, otherwise Ed25519 with a labelled deviation (state which on the page). KEM parameter set: the pinned revision names its pqkem (the spec's example is CRYSTALS-KYBER-1024); the page must state which KEM it runs, and that Kyber round-3 and FIPS 203 ML-KEM are not wire-compatible.
- Accent (--accent): #FF7EB6
- Favicon emoji:     📡
- In scope:          Bob's bundle: IK_B, SPK_B with signature, a last-resort PQSPK_B with signature, a one-time PQOPK_B with signature, OPK_B. Alice's side: EK_A, DH1–DH4, KEM encapsulation to the PQ prekey → ciphertext and shared secret. The KDF input F ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ SS with F = 32 bytes of 0xFF for curve25519, the info string, and the associated data — take the exact concatenation, the associated-data contents and the revision-2 binding of the KEM material from the pinned revision (the revision 1 → 2 diff is published in the Inria-Prosecco analysis artifact). The initial message, Bob's derivation, and byte-for-byte SK comparison. The quantum-adversary model: the adversary is handed every X25519 private key (a model, stated as one; no discrete-log break is computed) → DH1–DH4 open, SS stays closed, SK stays closed; a second toggle hands it SS (a modelled lattice break) → SK opens only with both. One-time versus last-resort PQ prekey: a reuse toggle showing two sessions sharing the KEM public key and what the pinned revision says that leaks. A diff panel: X3DH versus PQXDH, byte by byte, in the KDF input and the message.
- Non-goals:         The Double Ratchet proper (cross-link Ratchet Wire; this lab builds only a one-step DH-ratchet model for the second negative claim); SPQR / Triple Ratchet (the next lab); deniability proofs; prekey server behaviour; any real quantum algorithm (cross-link Shor).
```

## Rules this brief follows — keep them while building

This brief asserts no counts about the catalog. Every "the catalog has / lacks X" sentence is written as a grep to run, because the author could not run it. Run each pre-build check and report the result before writing code. If a grep shows the headline mechanism is already taught by a live card, stop and report; do not build a duplicate.

In addition to this lab's own sections below:

1. Port: `grep -rhoE "localhost:[0-9]+" ../crypto-lab-*/playwright.config.ts | sort -u`, pick an unused port in 4600–4700, commit it (template §4.1). Never the Vite default 4173.
2. Accessibility gate: copy `e2e/gate.ts`, `contrast.ts`, `nontext.ts`, `nontext-baseline.ts`, `a11y.spec.ts` from `crypto-lab-schnorr-forge` and rewrite every lab-specific passage (§4.1). Do not copy the gate from any other lab.
3. Claims suite in `e2e/claims.spec.ts` (§4.1b), mutation discipline (§4.1c), and the negative claim with its evidence fixture (§4.1d). The twin-verdict wording in this brief is a shape, not a string to hard-code.
4. README per §5; deploy per §6 with `.github/dependabot.yml`, the auto-merge job, the deploy dispatch, `timeout-minutes` on the job, `LICENSE`, `.gitignore`.
5. After the lab is live: the catalog card, then the five checkers run from the catalog repo (`readme-sync`, `corpus-sync`, `concept-sync`, `theme-sync`, `fleet-sync`). That step is done in `crypto-lab/`, not here; do not edit shared catalog files from this repo.
6. Category placement below is a proposal. Check the live chip list and section list before adding a chip; if a proposed chip does not exist, report the resulting chip-bar split rather than creating it silently. If the catalog keeps a concept-coverage document, the new concept boundary is added there in the same commit as the card.
7. Each non-goal in the SCOPE list gets its one-line "what this isn't" note in the UI (§1).
8. No emoji anywhere in content; the favicon data-URI is the only sanctioned use.
9. Every hard citation below was checked against its primary source on 2026-09-10 except where marked "verify" — resolve those before the README cites them. Do not cite anything the README cannot link.

**Accent.** This lab's `--accent` is ``#FF7EB6``, assigned centrally for the seven-lab batch of 2026-09-10. The other six batch accents are reserved — do not use them:

| Lab | Repo | `--accent` |
|---|---|---|
| Hidden Bit | crypto-lab-hidden-bit | ``#E4572E`` |
| Privacy Pass | crypto-lab-privacy-pass | ``#F2C14E`` |
| Order Leak | crypto-lab-order-leak | ``#A06CD5`` |
| Split Point | crypto-lab-split-point | ``#4CC9F0`` |
| Proof Tally | crypto-lab-proof-tally | ``#7BE495`` |
| Fold Gate | crypto-lab-fold-gate | ``#5E7CE2`` |

If `theme-sync` reports an adjacent-card collision after the card is placed, change this lab's accent, never the neighbour's, and record the change in the batch document.

## Hero

- Title: `PQXDH Wire`
- Subtitle: `Post-quantum asynchronous handshake · Signal PQXDH`
- Description: Run the handshake Signal actually deploys — four X25519 agreements and one ML-KEM encapsulation into a single HKDF — then hand the adversary a quantum computer and watch four boxes open and the fifth stay shut.
- Why it matters: Traffic recorded today is decrypted the day a large quantum computer exists. PQXDH is the first widely deployed answer to that, and its own specification says which promises it keeps against a quantum adversary and which it does not yet.

## §1 sections

**SCOPE** — as in the brief.

**SECURITY / CORRECTNESS INVARIANTS**
1. RFC 7748 X25519 vectors, RFC 5869 HKDF vectors and the ML-KEM library's FIPS 203 KATs pass; state counts. F is 32 bytes of 0xFF for curve25519 per the spec — a test asserts it (an earlier audit found the F prefix missing in a sibling lab).
2. SK is computed independently by the Alice and Bob modules and compared byte for byte; the compare lives in `src/verify/`.
3. Signature verification over SPK and the PQ prekeys is mandatory and fail-closed; Alice aborts on a bad signature (test).
4. The quantum-adversary module receives exactly the private keys the model grants; tests assert its inputs with and without the lattice toggle. It "recovers SK" only by recomputing the KDF from recovered inputs, and the page shows that recomputation, never a flag.
5. Modes that hand the adversary keys are marked MODEL, never default; each carries its "what this isn't" line.
6. Search for published PQXDH transcript vectors (libsignal) before building; if found, use them; if not, state that on the page and in Build & Verify and rely on component KATs plus the independent re-derivation below. Do not assert their absence beyond "none found on <date>".

**ARCHITECTURE** — `src/pqxdh/{bundle,alice,bob,kdf}.ts`, `src/model/{quantum,ratchet-step}.ts`, `src/diff/x3dh-vs-pqxdh.ts`, `src/verify/`, `src/ui/`.

**UI** — Central metaphor: the KDF input as a row of six sealed boxes: F, DH1, DH2, DH3, DH4, SS, feeding the SK box. The quantum toggle turns the four DH boxes transparent while SS stays opaque and SK stays locked; the lattice toggle turns SS transparent and SK opens. Steps: publish bundle → Alice computes → send → Bob computes → compare SK → toggle adversaries → toggle prekey reuse → open the diff panel.

**VISUAL SEMANTICS** — SK match is green (correctness). Boxes the adversary opened are ALARM. SK locked under the quantum toggle is neutral "STILL LOCKED (under this model)" — not green; the lesson is which box is opaque under which assumption, never "secure". The impersonation fixture reads "PQ-CONFIDENTIAL — AND IMPERSONATED"; the ratchet fixture reads "HEALED — AND STILL READ". Icon + text + colour.

**EDGE CASES** — no one-time PQ prekey available → last-resort fallback (spec behaviour; show the leakage difference); bad signature → abort with cause; tampered KEM ciphertext → implicit rejection, and the mismatch surfaces at the first AEAD, not at decapsulation (cross-link KEM Trap); IK_A = IK_B (refuse); OPK exhausted.

**EXTENSION SEAMS** — the `ratchet-step.ts` boundary where SPQR / Triple Ratchet will attach; a deniability panel; a libsignal-vector loader if vectors are found.

## Claims suite and negative claims

`e2e/claims.spec.ts`: parse the displayed DH outputs and SS, recompute HKDF in the test (Node `crypto`) and assert it equals the displayed SK; assert Alice's and Bob's SK are equal; assert the bad-signature path names the cause; under the quantum toggle alone assert the recomputation panel shows SS unknown and SK not derived, and under both toggles assert the recomputed SK equals the honest SK; retirement on a new bundle; no-op guard; `[hidden]` probe.

**Negative claim 1 (§4.1d, required):** "PQXDH's post-quantum guarantee is forward secrecy of the session key. Authentication of the prekey bundle is a classical signature — the specification says so — and an adversary who can forge it is authenticated as Bob with every check green." **Fixture:** quantum toggle plus an active mode that hands the adversary Bob's identity signing key (MODEL): it substitutes the bundle, the signatures verify, Alice derives SK with the adversary → "PQ-CONFIDENTIAL — AND IMPERSONATED". Cite the spec's own sentence that authentication in PQXDH is not quantum-secure (present in the revision fetched 2026-09-10).

**Negative claim 2 (required — it is the reason the next lab exists):** "After PQXDH, the Double Ratchet's self-healing uses X25519 alone. A state compromise heals against a classical adversary and not against one who can read every later DH." **Fixture:** the one-step DH-ratchet model — hand the adversary the root key after PQXDH (a compromise, MODEL), run three DH ratchet steps: with the quantum toggle off the adversary cannot compute the next root (it lacks the new private keys) and the page says HEALED; with it on, it follows every step → "HEALED — AND STILL READ". State on the page that this is a reduced model of the Double Ratchet and link Ratchet Wire. Point to Signal's SPQR announcement as where this goes next; verify the post's date before citing it.

## Pre-build verification

- Grep card copy for `PQXDH`, `post-quantum X3DH`. Read X3DH Wire for its library choices, its signature scheme and its handling of F, and match them.
- Pin the PQXDH revision; read its §3 and §4 for the associated data, the KEM binding introduced in revision 2, and the one-time / last-resort prekey text.
- Verify: does the named ML-KEM library ship FIPS 203 KATs? Does libsignal publish PQXDH transcript vectors? Record both answers with dates.
- Proposed section: Key Exchange. Proposed chips: KEY EXCHANGE and POST-QUANTUM — verify whether a card may carry two chips; if not, KEY EXCHANGE.

## Citations (checked unless marked verify)

Kret & Schmidt, "The PQXDH Key Agreement Protocol", Signal (spec page fetched 2026-09-10; the revision number and date go in the README from the spec's own revision history, not from secondary sources). Bhargavan, Jacomme, Kiefer, Schmidt, "Formal verification of the PQXDH Post-Quantum key agreement protocol for end-to-end secure messaging", USENIX Security 2024 (confirmed), with the Inria-Prosecco `pqxdh-analysis` artifact and its revision 1 → 2 diff. Marlinspike & Perrin, "The X3DH Key Agreement Protocol", Signal, 2016. FIPS 203. RFC 7748. RFC 5869. Signal, SPQR / Triple Ratchet announcement, 2025 — verify.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*