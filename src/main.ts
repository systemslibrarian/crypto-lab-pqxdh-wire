import './styles.css'

import { bytesToHex, equalBytes, shortHex } from './crypto/bytes.js'
import { runAlice, type AliceResult } from './pqxdh/alice.js'
import { runBob, type BobResult } from './pqxdh/bob.js'
import { createBobState, publishBundle } from './pqxdh/bundle.js'
import { F_PREFIX } from './pqxdh/kdf.js'
import type { BobPrivateState, PublicBundle } from './pqxdh/types.js'
import {
  createAdversaryGrant,
  recomputeAsAdversary,
  runImpersonationFixture,
} from './model/quantum.js'
import { runRatchetModel } from './model/ratchet-step.js'
import { sessionKeysMatch } from './verify/match.js'
import { TRANSCRIPT_DIFF } from './diff/x3dh-vs-pqxdh.js'

const app = document.querySelector<HTMLElement>('#app')
if (!app) throw new Error('Missing #app mount')

const diffRows = TRANSCRIPT_DIFF.map(
  (row) => `
    <tr class="${row.changed ? 'diff-changed' : ''}">
      <th scope="row">${row.field}</th>
      <td>${row.x3dh}</td>
      <td>${row.pqxdh}</td>
    </tr>`,
).join('')

app.innerHTML = `
  <div class="shell">
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">PQXDH Wire</h1>
        <p class="cl-hero-sub">Post-quantum asynchronous handshake · Signal PQXDH · Revision 3</p>
        <p class="cl-hero-desc">Run four real X25519 agreements and one real ML-KEM encapsulation into a single HKDF, then expose each input to two modeled adversaries.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">Traffic recorded today may be attacked when a large quantum computer exists. PQXDH protects the initial session key against that future decryption threat, while leaving authentication and later classical ratcheting as separate problems.</p>
      </aside>
    </header>

    <section class="intro-band" aria-labelledby="intro-title">
      <p class="eyebrow">THE IDEA</p>
      <h2 id="intro-title">Five secrets enter. Breaking only four is not enough.</h2>
      <div class="intro-copy">
        <p>PQXDH is a way to start an encrypted conversation while Bob is offline. Alice combines the classical key agreements used by X3DH with one post-quantum KEM secret; both parties independently turn that exact transcript into the same session key.</p>
        <p>The locks below represent what an adversary knows under a stated model, not whether a value is visible in this teaching page. This is not production crypto software.</p>
      </div>
    </section>

    <section class="workbench-band" aria-labelledby="workbench-title">
      <div class="section-heading">
        <div>
          <p class="eyebrow">LIVE HANDSHAKE</p>
          <h2 id="workbench-title">Build the transcript</h2>
        </div>
        <div class="workbench-actions">
          <button class="button button-secondary" id="reset-button" type="button">Reset</button>
          <button class="button button-primary" id="step-button" type="button">Publish Bob's bundle</button>
        </div>
      </div>

      <ol class="step-track" aria-label="Handshake progress">
        <li data-progress="1"><span>01</span> Publish bundle</li>
        <li data-progress="2"><span>02</span> Alice computes</li>
        <li data-progress="3"><span>03</span> Send</li>
        <li data-progress="4"><span>04</span> Bob computes</li>
        <li data-progress="5"><span>05</span> Compare</li>
      </ol>

      <div class="protocol-status" id="protocol-status" data-verdict="handshake-status" role="status" aria-live="polite">
        READY — no key material generated yet
      </div>

      <section class="bundle-strip" id="bundle-panel" aria-labelledby="bundle-title" hidden>
        <div>
          <span class="mini-label">BOB'S PUBLISHED BUNDLE</span>
          <strong id="bundle-title">Signatures verified before any secret is derived</strong>
        </div>
        <dl class="bundle-values">
          <div><dt>SPK_B</dt><dd id="bundle-spk">pending</dd></div>
          <div><dt>OPK_B</dt><dd id="bundle-opk">pending</dd></div>
          <div><dt>PQOPK_B</dt><dd id="bundle-pq">pending</dd></div>
        </dl>
      </section>

      <div class="kdf-stage" role="group" aria-label="PQXDH key derivation input">
        <div class="material-row" data-verdict="kdf-input-state" role="list">
          ${materialBox('F', 'Domain separator', 'value-f')}
          ${materialBox('DH1', 'IK_A × SPK_B', 'value-dh1')}
          ${materialBox('DH2', 'EK_A × IK_B', 'value-dh2')}
          ${materialBox('DH3', 'EK_A × SPK_B', 'value-dh3')}
          ${materialBox('DH4', 'EK_A × OPK_B', 'value-dh4')}
          ${materialBox('SS', 'ML-KEM secret', 'value-ss')}
        </div>
        <div class="flow-line" aria-hidden="true"><span></span><b>HKDF-SHA-512</b><span></span></div>
        <div class="session-key-box" data-material="SK" data-verdict="session-key-state">
          <div>
            <span class="material-name">SK</span>
            <span class="material-detail">32-byte session key</span>
          </div>
          <span class="material-state"><i class="state-icon" aria-hidden="true"></i><b data-state-label>WAITING</b></span>
          <code data-test="value-sk">not derived</code>
        </div>
      </div>

      <section class="message-strip" id="message-panel" aria-labelledby="message-title" hidden>
        <div>
          <span class="mini-label">INITIAL MESSAGE</span>
          <strong id="message-title">Alice sends public keys, prekey IDs, ML-KEM ciphertext, and AES-GCM ciphertext</strong>
        </div>
        <dl class="message-metrics">
          <div><dt>KEM CT</dt><dd>1,568 B</dd></div>
          <div><dt>AD</dt><dd>1,632 B</dd></div>
          <div><dt>Secret sent</dt><dd>0 B</dd></div>
        </dl>
      </section>

      <section class="comparison" id="comparison-panel" aria-labelledby="comparison-title" hidden>
        <div class="verdict" id="comparison-verdict" data-verdict="session-key-match">
          <span class="verdict-icon" aria-hidden="true"></span>
          <div><span class="mini-label">BYTE-FOR-BYTE VERDICT</span><strong id="comparison-title">Session keys not compared yet</strong></div>
        </div>
        <dl class="key-compare">
          <div><dt>Alice</dt><dd><code data-test="alice-sk">pending</code></dd></div>
          <div><dt>Bob</dt><dd><code data-test="bob-sk">pending</code></dd></div>
        </dl>
      </section>
    </section>

    <section class="threat-band" aria-labelledby="threat-title">
      <div class="section-heading">
        <div>
          <p class="eyebrow">ADVERSARY WORKBENCH</p>
          <h2 id="threat-title">Open the boxes the model grants</h2>
        </div>
        <span class="model-badge">MODEL — no quantum algorithm runs here</span>
      </div>
      <fieldset id="threat-controls" disabled>
        <legend class="sr-only">Adversary capabilities</legend>
        <label class="switch-control">
          <input type="checkbox" id="quantum-toggle" />
          <span class="switch" aria-hidden="true"></span>
          <span><strong>Curve break</strong><small>Hand the model every X25519 private key</small></span>
        </label>
        <label class="switch-control">
          <input type="checkbox" id="lattice-toggle" disabled />
          <span class="switch" aria-hidden="true"></span>
          <span><strong>Lattice break</strong><small>Also hand the model the ML-KEM shared secret</small></span>
        </label>
      </fieldset>
      <div class="recompute-panel" id="recompute-panel" data-verdict="adversary-model" role="status" aria-live="polite">
        Complete the handshake to enable the adversary model.
      </div>
      <p class="what-this-isnt"><strong>What this isn't:</strong> the browser does not run Shor's algorithm or break ML-KEM. Private values are deliberately handed to a recomputation module so its inputs can be inspected and tested.</p>
    </section>

    <section class="break-band" aria-labelledby="break-title">
      <div class="section-heading">
        <div>
          <p class="eyebrow">BREAK IT YOURSELF</p>
          <h2 id="break-title">Make the real checks answer</h2>
        </div>
      </div>
      <div class="break-grid">
        <article class="break-item">
          <span class="item-index">01 / AUTHENTICATION</span>
          <h3>Corrupt a prekey signature</h3>
          <p>Alice must stop before generating an ephemeral key or KEM ciphertext.</p>
          <button class="button button-secondary" id="bad-signature-button" type="button">Corrupt and verify</button>
          <output id="bad-signature-output" class="fixture-output" data-verdict="prekey-signature-abort" aria-live="polite">Not run</output>
        </article>
        <article class="break-item">
          <span class="item-index">02 / IMPLICIT REJECTION</span>
          <h3>Flip one KEM ciphertext bit</h3>
          <p>ML-KEM returns a different secret; the first AES-GCM check exposes the mismatch.</p>
          <button class="button button-secondary" id="tamper-button" type="button">Tamper and deliver</button>
          <output id="tamper-output" class="fixture-output" data-verdict="kem-tamper-abort" aria-live="polite">Not run</output>
        </article>
        <article class="break-item">
          <span class="item-index">03 / PREKEY SUPPLY</span>
          <h3>Exhaust one-time PQ prekeys</h3>
          <p>Two sessions fall back to the same signed last-resort ML-KEM public key.</p>
          <label class="switch-control compact">
            <input type="checkbox" id="reuse-toggle" />
            <span class="switch" aria-hidden="true"></span>
            <span><strong>Reuse last-resort key</strong></span>
          </label>
          <output id="reuse-output" class="fixture-output" data-verdict="last-resort-reuse" aria-live="polite">One-time PQ prekeys are available</output>
        </article>
      </div>
    </section>

    <section class="limits-band" aria-labelledby="limits-title">
      <div class="section-heading">
        <div>
          <p class="eyebrow">WHAT PQXDH DOES NOT BUY</p>
          <h2 id="limits-title">Two green handshakes, two missing guarantees</h2>
        </div>
      </div>
      <div class="limit-grid">
        <article class="limit-item">
          <span class="model-badge">MODEL — ACTIVE QUANTUM ADVERSARY</span>
          <h3>Classical authentication can be forged</h3>
          <p>PQXDH's post-quantum guarantee protects forward secrecy of the session key. Its prekey signature is classical, so a model granted Bob's signing and curve identity secrets can publish its own valid bundle.</p>
          <button class="button button-alarm" id="impersonate-button" type="button">Substitute signed bundle</button>
          <output id="impersonate-output" class="fixture-output" data-verdict="impersonation" aria-live="polite">Not run</output>
        </article>
        <article class="limit-item">
          <span class="model-badge">REDUCED DOUBLE RATCHET MODEL</span>
          <h3>Classical healing is not quantum healing</h3>
          <p>After a root-key compromise, three fresh X25519 steps heal against a classical observer. A model that receives each later curve private key follows every new root.</p>
          <button class="button button-alarm" id="ratchet-button" type="button">Compromise and ratchet</button>
          <output id="ratchet-output" class="fixture-output" data-verdict="ratchet-heal" aria-live="polite">Not run</output>
        </article>
      </div>
      <p class="what-this-isnt"><strong>What this isn't:</strong> this is one DH-root update, not the Double Ratchet message-key schedule, skipped-key handling, or full protocol. SPQR and the Triple Ratchet add post-quantum healing; deniability proofs and prekey-server behavior are also out of scope.</p>
    </section>

    <section class="detail-band" aria-labelledby="detail-title">
      <p class="eyebrow">BYTE-LEVEL DIFFERENCE</p>
      <h2 id="detail-title">X3DH becomes PQXDH at one boundary</h2>
      <details>
        <summary>Open the transcript diff</summary>
        <div class="table-scroll" tabindex="0" role="region" aria-label="X3DH and PQXDH transcript comparison">
          <table>
            <thead><tr><th>Field</th><th>X3DH</th><th>PQXDH Revision 3 profile</th></tr></thead>
            <tbody>${diffRows}</tbody>
          </table>
        </div>
      </details>
      <details>
        <summary>Implementation profile and deviations</summary>
        <div class="disclosure-copy">
          <p><strong>Real:</strong> Noble X25519 and strict Ed25519, Noble ML-KEM-1024, HKDF-SHA-512, and WebCrypto AES-256-GCM. Alice and Bob derive independently. Keys exist only in memory and a reset replaces them.</p>
          <p><strong>Profile:</strong> <code>F || DH1 || DH2 || DH3 || DH4 || SS</code>, zero SHA-512-length salt, and info <code>PQXDH_CURVE25519_SHA-512_ML-KEM-1024</code>. Associated data binds <code>IK_A || IK_B || PQPK_B</code>.</p>
          <p><strong>Deviation:</strong> Revision 3 specifies XEdDSA and gives CRYSTALS-KYBER-1024 as its example. This browser lab uses separate strict Ed25519 signatures and standardized FIPS 203 ML-KEM-1024. Kyber round 3 and ML-KEM are not wire-compatible.</p>
          <p><strong>Verification scope:</strong> three spec KATs pass: one RFC 7748 X25519 vector, one RFC 5869 HKDF vector, and NIST ACVP FIPS 203 ML-KEM-1024 keyGen case tgId 3 / tcId 51. No stable byte-for-byte libsignal PQXDH transcript vector was found in the public repository search on 2026-09-11, so independent peer derivation closes that gap.</p>
        </div>
      </details>
    </section>

    <section class="sources-band" id="sources" aria-labelledby="sources-title">
      <p class="eyebrow">PRIMARY SOURCES</p>
      <h2 id="sources-title">Pinned protocol record</h2>
      <ul class="source-list">
        <li><a href="https://signal.org/docs/specifications/pqxdh/">Kret &amp; Schmidt, The PQXDH Key Agreement Protocol</a><span>Revision 3 · 2023-05-24 · updated 2024-01-23</span></li>
        <li><a href="https://www.rfc-editor.org/rfc/rfc7748">RFC 7748</a><span>X25519 known-answer vectors</span></li>
        <li><a href="https://www.rfc-editor.org/rfc/rfc5869">RFC 5869</a><span>HKDF known-answer vectors</span></li>
        <li><a href="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</a><span>ML-KEM standard</span></li>
        <li><a href="https://signal.org/blog/spqr/">Signal Protocol and Post-Quantum Ratchets</a><span>2025-10-02 · SPQR and Triple Ratchet</span></li>
        <li><a href="https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan">Bhargavan et al., Formal Verification of PQXDH</a><span>USENIX Security 2024</span></li>
      </ul>
    </section>
  </div>
  <footer class="scripture-footer">
    <p>So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31</p>
  </footer>
`

function materialBox(name: string, detail: string, testId: string): string {
  return `
    <div class="material-box" data-material="${name}" role="listitem">
      <div><span class="material-name">${name}</span><span class="material-detail">${detail}</span></div>
      <span class="material-state"><i class="state-icon" aria-hidden="true"></i><b data-state-label>SEALED</b></span>
      <code data-test="${testId}">${name === 'F' ? bytesToHex(F_PREFIX) : 'not derived'}</code>
    </div>`
}

const requiredElement = <ElementType extends HTMLElement>(selector: string): ElementType => {
  const element = document.querySelector<ElementType>(selector)
  if (!element) throw new Error(`Missing element: ${selector}`)
  return element
}

let step = 0
let bobState: BobPrivateState | undefined
let bundle: PublicBundle | undefined
let alice: AliceResult | undefined
let bob: BobResult | undefined

const stepButton = requiredElement<HTMLButtonElement>('#step-button')
const resetButton = requiredElement<HTMLButtonElement>('#reset-button')
const protocolStatus = requiredElement<HTMLElement>('#protocol-status')
const threatControls = requiredElement<HTMLFieldSetElement>('#threat-controls')
const quantumToggle = requiredElement<HTMLInputElement>('#quantum-toggle')
const latticeToggle = requiredElement<HTMLInputElement>('#lattice-toggle')

const stepLabels = [
  "Publish Bob's bundle",
  'Alice computes five secrets',
  'Send initial message',
  'Bob derives independently',
  'Compare 32 bytes',
  'Run a fresh handshake',
]

stepButton.addEventListener('click', () => void advanceHandshake())
resetButton.addEventListener('click', resetHandshake)
quantumToggle.addEventListener('change', () => {
  latticeToggle.disabled = !quantumToggle.checked
  if (!quantumToggle.checked) latticeToggle.checked = false
  renderThreatModel()
})
latticeToggle.addEventListener('change', renderThreatModel)

async function advanceHandshake(): Promise<void> {
  if (step === 5) {
    resetHandshake()
    return
  }
  stepButton.disabled = true
  try {
    if (step === 0) {
      bobState = createBobState()
      bundle = publishBundle(bobState)
      protocolStatus.textContent = 'BUNDLE PUBLISHED — Ed25519 signatures cover SPK_B and PQOPK_B'
    } else if (step === 1 && bundle) {
      alice = await runAlice(bundle)
      protocolStatus.textContent = 'ALICE COMPLETE — four DH outputs and one ML-KEM secret entered HKDF'
    } else if (step === 2 && alice) {
      protocolStatus.textContent = 'MESSAGE SENT — no shared secret or private key crossed the wire'
    } else if (step === 3 && bobState && bundle && alice) {
      bob = await runBob(bobState, bundle, alice.message)
      protocolStatus.textContent = 'BOB COMPLETE — decapsulation, four DH operations, and AEAD verification passed'
    } else if (step === 4 && alice && bob) {
      protocolStatus.textContent = sessionKeysMatch(alice.sessionKey, bob.sessionKey)
        ? 'MATCH — both modules independently derived the same 32 bytes'
        : 'ABORT — Alice and Bob derived different keys'
    }
    step += 1
    renderHandshake()
  } catch (error) {
    protocolStatus.textContent = `ABORT — ${error instanceof Error ? error.message : 'unknown error'}`
  } finally {
    stepButton.disabled = false
  }
}

function resetHandshake(): void {
  step = 0
  bobState = undefined
  bundle = undefined
  alice = undefined
  bob = undefined
  quantumToggle.checked = false
  latticeToggle.checked = false
  latticeToggle.disabled = true
  threatControls.disabled = true
  protocolStatus.textContent = 'READY — no key material generated yet'
  renderHandshake()
  renderThreatModel()
}

function renderHandshake(): void {
  stepButton.textContent = stepLabels[step]
  document.querySelectorAll<HTMLElement>('[data-progress]').forEach((item) => {
    const itemStep = Number(item.dataset.progress)
    item.dataset.complete = String(itemStep <= step)
    item.setAttribute('aria-current', itemStep === step + 1 ? 'step' : 'false')
  })

  const bundlePanel = requiredElement<HTMLElement>('#bundle-panel')
  bundlePanel.hidden = step < 1
  if (bundle) {
    requiredElement('#bundle-spk').textContent = bundle.signedPrekeyId
    requiredElement('#bundle-opk').textContent = bundle.oneTimePrekeyId ?? 'exhausted'
    requiredElement('#bundle-pq').textContent = `${bundle.pqPrekeyId} · ${bundle.pqPrekeyKind}`
  }

  requiredElement<HTMLElement>('#message-panel').hidden = step < 3
  requiredElement<HTMLElement>('#comparison-panel').hidden = step < 5
  threatControls.disabled = step < 5

  if (alice && step >= 2) {
    setValue('value-dh1', alice.components.dh1)
    setValue('value-dh2', alice.components.dh2)
    setValue('value-dh3', alice.components.dh3)
    setValue('value-dh4', alice.components.dh4)
    setValue('value-ss', alice.components.sharedSecret)
    setValue('value-sk', alice.sessionKey)
    for (const name of ['DH1', 'DH2', 'DH3', 'DH4', 'SS']) {
      setMaterialState(name, 'derived', 'HONEST INPUT')
    }
    if (step < 5 || !bob) {
      setMaterialState('SK', 'derived', 'DERIVED')
    } else {
      const matched = sessionKeysMatch(alice.sessionKey, bob.sessionKey)
      setMaterialState('SK', matched ? 'pass' : 'alarm', matched ? 'MATCHED' : 'DIVERGED')
    }
  } else {
    for (const name of ['DH1', 'DH2', 'DH3', 'DH4', 'SS']) {
      setMaterialState(name, 'sealed', 'SEALED')
      const output = document.querySelector<HTMLElement>(`[data-test="value-${name.toLowerCase()}"]`)
      if (output) output.textContent = 'not derived'
    }
    setMaterialState('SK', 'sealed', 'WAITING')
    requiredElement('[data-test="value-sk"]').textContent = 'not derived'
  }

  renderComparison()
}

/**
 * The byte-for-byte verdict. This markup used to ship `ALICE SK = BOB SK`
 * hard-coded in `verdict-pass` styling with nothing ever rewriting it, so the
 * page stated the outcome of a comparison it never made.
 */
function renderComparison(): void {
  const panel = requiredElement<HTMLElement>('#comparison-panel')
  const verdict = requiredElement<HTMLElement>('#comparison-verdict')
  const title = requiredElement<HTMLElement>('#comparison-title')
  if (step < 5 || !alice || !bob) {
    panel.dataset.outcome = 'pending'
    verdict.classList.remove('verdict-pass', 'verdict-alarm')
    title.textContent = 'Session keys not compared yet'
    return
  }
  const matched = sessionKeysMatch(alice.sessionKey, bob.sessionKey)
  requiredElement('[data-test="alice-sk"]').textContent = bytesToHex(alice.sessionKey)
  requiredElement('[data-test="bob-sk"]').textContent = bytesToHex(bob.sessionKey)
  panel.dataset.outcome = matched ? 'pass' : 'alarm'
  verdict.classList.toggle('verdict-pass', matched)
  verdict.classList.toggle('verdict-alarm', !matched)
  title.textContent = matched
    ? 'ALICE SK = BOB SK'
    : 'ALICE SK DIFFERS FROM BOB SK — the 32 bytes below are not equal'
}

function setValue(testId: string, value: Uint8Array | undefined): void {
  const element = requiredElement<HTMLElement>(`[data-test="${testId}"]`)
  element.textContent = value ? bytesToHex(value) : 'omitted — OPK exhausted'
  element.title = value ? bytesToHex(value) : 'DH4 omitted by the protocol'
}

function setMaterialState(name: string, state: string, label: string): void {
  const box = requiredElement<HTMLElement>(`[data-material="${name}"]`)
  box.dataset.state = state
  requiredElement<HTMLElement>(`[data-material="${name}"] [data-state-label]`).textContent = label
}

function currentSession() {
  if (!bobState || !bundle || !alice || !bob) return undefined
  return { bobState, bundle, alice, bob, keysMatch: sessionKeysMatch(alice.sessionKey, bob.sessionKey) }
}

function renderThreatModel(): void {
  const output = requiredElement<HTMLElement>('#recompute-panel')
  const session = currentSession()
  if (!session || step < 5) {
    output.textContent = 'Complete the handshake to enable the adversary model.'
    return
  }
  if (!quantumToggle.checked) {
    for (const name of ['DH1', 'DH2', 'DH3', 'DH4', 'SS']) {
      setMaterialState(name, 'derived', 'HONEST INPUT')
    }
    setMaterialState(
      'SK',
      session.keysMatch ? 'pass' : 'alarm',
      session.keysMatch ? 'MATCHED' : 'DIVERGED',
    )
    output.innerHTML = '<strong>NO MODEL ACTIVE</strong><span>Adversary inputs: public transcript only</span>'
    return
  }

  const grant = createAdversaryGrant(session, latticeToggle.checked)
  const result = recomputeAsAdversary(session, grant)
  for (const name of ['DH1', 'DH2', 'DH3', 'DH4']) setMaterialState(name, 'alarm', 'OPENED IN MODEL')
  if (latticeToggle.checked && result.sessionKey) {
    setMaterialState('SS', 'alarm', 'OPENED IN MODEL')
    setMaterialState('SK', 'alarm', 'RECOMPUTED')
    output.innerHTML = `<strong>SK OPENED — BOTH ASSUMPTIONS BROKEN</strong><span data-test="adversary-sk">${bytesToHex(result.sessionKey)}</span>`
  } else {
    setMaterialState('SS', 'sealed', 'OPAQUE TO MODEL')
    setMaterialState('SK', 'locked', 'STILL LOCKED (UNDER THIS MODEL)')
    output.innerHTML = '<strong>SS = UNKNOWN · SK = NOT DERIVED</strong><span>Four X25519 outputs are insufficient input to HKDF.</span>'
  }
}

requiredElement<HTMLButtonElement>('#bad-signature-button').addEventListener('click', async () => {
  const output = requiredElement<HTMLOutputElement>('#bad-signature-output')
  const state = createBobState()
  const candidate = publishBundle(state)
  candidate.pqPrekeySignature = candidate.pqPrekeySignature.slice()
  candidate.pqPrekeySignature[0] ^= 1
  try {
    await runAlice(candidate)
    output.dataset.result = 'pass'
    output.textContent = 'UNEXPECTED ACCEPT — invariant violated'
  } catch (error) {
    output.dataset.result = 'alarm'
    output.textContent = `ABORT — ${error instanceof Error ? error.message : 'verification failed'}`
  }
})

requiredElement<HTMLButtonElement>('#tamper-button').addEventListener('click', async () => {
  const output = requiredElement<HTMLOutputElement>('#tamper-output')
  const state = createBobState()
  const candidate = publishBundle(state)
  const sender = await runAlice(candidate)
  sender.message.kemCiphertext = sender.message.kemCiphertext.slice()
  sender.message.kemCiphertext[0] ^= 1
  try {
    await runBob(state, candidate, sender.message)
    output.dataset.result = 'pass'
    output.textContent = 'UNEXPECTED ACCEPT — invariant violated'
  } catch (error) {
    output.dataset.result = 'alarm'
    output.textContent = `REJECTED AT FIRST AEAD — ${error instanceof Error ? error.message : 'authentication failed'}`
  }
})

requiredElement<HTMLInputElement>('#reuse-toggle').addEventListener('change', async (event) => {
  const checked = (event.currentTarget as HTMLInputElement).checked
  const output = requiredElement<HTMLOutputElement>('#reuse-output')
  if (!checked) {
    output.dataset.result = ''
    output.textContent = 'One-time PQ prekeys are available'
    return
  }
  const state = createBobState()
  const fallbackBundle = publishBundle(state, { useOneTimePq: false })
  const first = await runAlice(fallbackBundle)
  const second = await runAlice(fallbackBundle)

  // Measured, not narrated. "SAME PQ KEY ID" used to print whichever id the
  // bundle happened to carry, without ever comparing the two sessions or
  // checking that the served key was the last-resort one — a sentence true of
  // the fixture by construction rather than by observation.
  const checks: ReadonlyArray<readonly [string, boolean]> = [
    ['served key is the last-resort key', fallbackBundle.pqPrekeyKind === 'last-resort'],
    [
      'both sessions cite one PQ prekey id',
      first.message.pqPrekeyId === second.message.pqPrekeyId,
    ],
    [
      'per-session SS still differ',
      !equalBytes(first.components.sharedSecret, second.components.sharedSecret),
    ],
  ]
  const verdicts = checks
    .map(([name, passed]) => `${name}: ${passed ? 'PASS' : 'FAIL'}`)
    .join(' · ')
  const reused = checks.every(([, passed]) => passed)
  output.dataset.result = reused ? 'alarm' : 'pass'
  output.innerHTML = reused
    ? `<strong>SAME PQ KEY ID — ${fallbackBundle.pqPrekeyId}</strong><span data-test="reuse-checks">${verdicts}</span><span>Session SS values differ: ${shortHex(first.components.sharedSecret)} / ${shortHex(second.components.sharedSecret)}. Reuse does not reveal either SK by itself, but future compromise of this retained last-resort private key affects every session whose remaining inputs are also recovered.</span>`
    : `<strong>NO LAST-RESORT REUSE OBSERVED — a check did not report success</strong><span data-test="reuse-checks">${verdicts}</span>`
})

requiredElement<HTMLButtonElement>('#impersonate-button').addEventListener('click', async () => {
  const output = requiredElement<HTMLOutputElement>('#impersonate-output')
  const fixture = await runImpersonationFixture()
  const checks: ReadonlyArray<readonly [string, boolean]> = [
    ['SPK_B Ed25519 signature', fixture.signedPrekeySignatureValid],
    ['PQOPK_B Ed25519 signature', fixture.pqPrekeySignatureValid],
    ["signer is Bob's identity key", fixture.signedByBobsIdentity],
    ["Alice's initial AES-GCM message opened", fixture.initialMessageOpened],
  ]
  const verdicts = checks
    .map(([name, passed]) => `${name}: ${passed ? 'PASS' : 'FAIL'}`)
    .join(' · ')
  output.dataset.result = 'alarm'
  output.innerHTML = fixture.checksGreen
    ? `<strong>PQ-CONFIDENTIAL — AND IMPERSONATED</strong><span data-test="impersonate-checks">${verdicts}</span><span>Each verdict above was measured after the handshake, not assumed. The attacker derived ${shortHex(fixture.sessionKey)} with Alice.</span>`
    : `<strong>FIXTURE INVALID — a check did not report success</strong><span data-test="impersonate-checks">${verdicts}</span>`
})

requiredElement<HTMLButtonElement>('#ratchet-button').addEventListener('click', () => {
  const output = requiredElement<HTMLOutputElement>('#ratchet-output')
  const session = currentSession()
  if (!session) {
    output.textContent = 'Complete the live handshake first'
    return
  }
  const result = runRatchetModel(session.alice.sessionKey, quantumToggle.checked)
  // "HEALED" is now read off the measured chain rather than printed unconditionally.
  const chain = result.honestRoots
    .map((root) => bytesToHex(root.slice(0, 4)))
    .join(' → ')
  const roots = `<span data-test="ratchet-roots">Root chain: ${chain}</span>`
  output.dataset.result = result.healed && !result.stillReadable ? 'pass' : 'alarm'
  if (!result.healed) {
    output.innerHTML = `<strong>DID NOT HEAL — root chain did not advance</strong>${roots}`
    return
  }
  output.innerHTML = result.stillReadable
    ? `<strong>HEALED — AND STILL READ</strong>${roots}<span>Three honest root updates completed; the curve-break model recomputed all three.</span>`
    : `<strong>HEALED</strong>${roots}<span>Three honest root updates completed; the classical observer remained at the compromised root.</span>`
})

renderHandshake()