import { useTrace } from '@/state/TraceProvider';
export function WorkspaceSwitcher(){
 const t=useTrace();
 return <label className="workspace-switcher"><span>Пространство</span><select aria-label="Рабочее пространство" value={t.workspaceId} onChange={e=>t.setWorkspace(e.target.value)} disabled={!t.workspaces.length}>{!t.workspaces.some(w=>w.id===t.workspaceId)&&<option value={t.workspaceId}>{t.workspaces.length?'Выберите пространство':'Нет доступных пространств'}</option>}{t.workspaces.map(w=><option key={w.id} value={w.id}>{w.name}</option>)}</select></label>;
}
