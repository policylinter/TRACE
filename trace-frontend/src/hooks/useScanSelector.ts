import {
  getEvents,
  listScans,
  setActiveScan,
  type ScanEvent,
} from '@/lib/api';
import { useTrace } from '@/state/TraceProvider';

export function useScanSelector() {
  const { scan, scans, setActiveScan: select } = useTrace();
  return { scan, scans, select };
}
