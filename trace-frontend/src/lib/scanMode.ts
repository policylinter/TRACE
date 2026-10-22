import type { Scan } from './api';
// This ID is reserved for the backend seed fixture.
export function isDemoScan(scan: Scan | null): boolean { return scan?.id === 'scan-8f21a3c'; }
