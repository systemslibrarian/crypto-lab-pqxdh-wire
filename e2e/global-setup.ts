import { randomUUID } from 'node:crypto'

import { resetObservations } from './observations.js'

/**
 * Mints this run's id and empties the observation sink before the first worker
 * starts, so a file left behind by an earlier run cannot satisfy the runtime
 * coverage rule. The id is exported through the environment, which Playwright
 * hands to every worker it forks after this returns; `globalTeardown` reads the
 * same variable in this process. A sink line carrying any other id is ignored,
 * so the rule survives a truncation that did not happen.
 */
export default function globalSetup(): void {
  resetObservations(randomUUID())
}
