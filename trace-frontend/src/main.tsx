import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { getSelectedWorkspace } from './lib/api';
import { TraceProvider } from './state/TraceProvider';
import './index.css';
import './workbench.css';
import './premium.css';
import './lab7.css';

const container = document.getElementById('root');

if (!container) {
  throw new Error('TRACE: root container #root was not found in index.html');
}

// Remount the complete client state on scope changes. Pending callbacks from
// the old workspace cannot populate the new workspace's provider or pages.
function WorkspaceRoot() {
  const [scope, setScope] = React.useState(() => new URLSearchParams(window.location.hash.slice(1)).get('workspace') || getSelectedWorkspace());
  React.useEffect(() => {
    const changed = () => setScope(getSelectedWorkspace());
    window.addEventListener('trace:workspace-changed', changed);
    return () => window.removeEventListener('trace:workspace-changed', changed);
  }, []);
  return <TraceProvider key={scope}><App /></TraceProvider>;
}

ReactDOM.createRoot(container).render(
  <React.StrictMode>
    <WorkspaceRoot />
  </React.StrictMode>,
);
