/**
 * VEX scope selector. The document itself is generated server-side (see
 * `lib/api.ts` and the Python `pipeline/vex.py`) so the UI and the API always
 * emit byte-identical CSAF 2.0 output.
 */
export type VexScope = 'finding' | 'actionable' | 'all';
