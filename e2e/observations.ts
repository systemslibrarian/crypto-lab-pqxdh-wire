import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * The RUNTIME denominator for the verdict rules.
 *
 * Fix 1 asked that every recorded kill go through `expectVerdict` /
 * `expectClaim`, and every lab in this lane implemented that as a SOURCE-TEXT
 * scan over `verdicts.spec.ts`. Three auditors defeated it three different
 * ways: comment the call out and the substring survives inside the comment;
 * keep the call but feed it values read off the page in the same test; rewrite
 * the killing assertion and let an unrelated call elsewhere in the file satisfy
 * a file-granular rule. A mention is not an assertion — which is the same
 * defect Fix 1 was written to close, one level down (lane decision D6).
 *
 * So the helpers record what they actually EXECUTED. Every successful
 * `expectVerdict` / `expectClaim` call appends one line naming the test that
 * ran it, the marker it asserted, and the claim it asserted — and the coverage
 * rule is checked against that file, not against the spec's source text.
 *
 * Playwright runs tests in separate worker processes, so a module-level `Set`
 * aggregates nothing. The sink is therefore a file, appended line-at-a-time
 * with `O_APPEND` (atomic for writes this small), truncated by `globalSetup` at
 * the start of every run and read back by `globalTeardown` after the last test.
 * Each line also carries the run id `globalSetup` minted, so a sink that
 * somehow survived truncation cannot satisfy the rule with a previous run's
 * observations.
 *
 * It lives under `test-results/` but NOT under `outputDir` — Playwright wipes
 * `outputDir` when the run starts, which would race the truncation above.
 * `playwright.config.ts` points `outputDir` at `test-results/artifacts` for
 * exactly that reason.
 */
export const OBSERVATIONS_PATH = fileURLToPath(
  new URL('../test-results/verdict-observations.ndjson', import.meta.url),
)

/** Set by `globalSetup`, read by the helpers and by `globalTeardown`. */
export const RUN_ID_ENV = 'PQXDH_VERDICT_RUN_ID'

export interface Observation {
  run: string
  test: string
  kind: 'verdict' | 'claim'
  id: string
  claim: string
}

/**
 * One claim, in one canonical form, so a record in `verdict-mutations.json` and
 * an argument passed at runtime compare byte-for-byte. Keys are sorted; a
 * RegExp becomes its own literal source (`/verdict-pass/`), which is what the
 * registry stores for `klass`.
 */
export function canonicalClaim(claim: Readonly<Record<string, unknown>>): string {
  const normalised: Record<string, unknown> = {}
  for (const key of Object.keys(claim).sort()) {
    const value = claim[key]
    if (value === undefined) continue
    normalised[key] = value instanceof RegExp ? String(value) : value
  }
  return JSON.stringify(normalised)
}

export function runId(): string {
  return process.env[RUN_ID_ENV] ?? ''
}

export function resetObservations(id: string): void {
  mkdirSync(dirname(OBSERVATIONS_PATH), { recursive: true })
  writeFileSync(OBSERVATIONS_PATH, '')
  process.env[RUN_ID_ENV] = id
}

export function recordObservation(observation: Observation): void {
  mkdirSync(dirname(OBSERVATIONS_PATH), { recursive: true })
  appendFileSync(OBSERVATIONS_PATH, `${JSON.stringify(observation)}\n`)
}

/** Every observation this run wrote. Lines from any other run are discarded. */
export function readObservations(id: string): Observation[] {
  let raw = ''
  try {
    raw = readFileSync(OBSERVATIONS_PATH, 'utf8')
  } catch {
    return []
  }
  return raw
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Observation)
    .filter((observation) => observation.run === id)
}
