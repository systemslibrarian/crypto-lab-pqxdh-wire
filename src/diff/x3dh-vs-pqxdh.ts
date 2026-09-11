export const TRANSCRIPT_DIFF = [
  { field: 'F', x3dh: '32 bytes', pqxdh: '32 bytes', changed: false },
  { field: 'DH1–DH4', x3dh: '128 bytes', pqxdh: '128 bytes', changed: false },
  { field: 'SS', x3dh: 'absent', pqxdh: '32 bytes', changed: true },
  { field: 'KDF input', x3dh: '160 bytes', pqxdh: '192 bytes', changed: true },
  { field: 'Initial message', x3dh: 'no KEM CT', pqxdh: 'adds 1,568-byte CT', changed: true },
] as const