import { defineConfig } from 'vitest/config'

export default defineConfig({
  base: '/crypto-lab-pqxdh-wire/',
  test: {
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: [
        'src/crypto/**/*.ts',
        'src/pqxdh/**/*.ts',
        'src/model/**/*.ts',
        'src/verify/**/*.ts',
      ],
      exclude: ['src/**/*.test.ts'],
      reporter: ['text', 'json-summary'],
      thresholds: {
        statements: 90,
        branches: 85,
        functions: 85,
        lines: 90,
      },
    },
  },
})