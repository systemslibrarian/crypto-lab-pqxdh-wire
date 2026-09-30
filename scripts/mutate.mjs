#!/usr/bin/env node
// Applies or reverts one recorded §4.1c mutation from e2e/verdict-mutations.json.
//
//   node scripts/mutate.mjs list
//   node scripts/mutate.mjs apply <id>
//   node scripts/mutate.mjs revert <id>
//
// A kill counts only when the unmutated baseline passed in the same run, the
// failure is the verdict's own assertion, and the server served the mutated
// code — so run the suite with CI=1, which turns off reuseExistingServer.
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const registry = JSON.parse(
  readFileSync(new URL('../e2e/verdict-mutations.json', import.meta.url), 'utf8'),
)
const [command, id] = process.argv.slice(2)

if (command === 'list' || !command) {
  for (const [key, entry] of Object.entries(registry.mutations)) {
    console.log(`${key}\n  ${entry.file}`)
    for (const [marker, kill] of Object.entries(entry.kills ?? {})) {
      console.log(`  kills ${marker} in: ${kill.test}`)
    }
    console.log(`  ${entry.why}\n`)
  }
  process.exit(0)
}

const entry = registry.mutations[id]
if (!entry) {
  console.error(`unknown mutation: ${id}`)
  process.exit(2)
}

const path = new URL(entry.file, `file://${root}`)
const source = readFileSync(path, 'utf8')
const [from, to] =
  command === 'apply' ? [entry.find, entry.replace] : [entry.replace, entry.find]
const occurrences = source.split(from).length - 1
if (occurrences !== 1) {
  console.error(`refusing: ${entry.file} matched ${occurrences}x, want exactly 1`)
  process.exit(2)
}
writeFileSync(path, source.replace(from, to))
console.log(`${command} ${id} -> ${entry.file}`)
