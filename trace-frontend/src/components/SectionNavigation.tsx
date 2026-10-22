import { NAV_GROUPS, primaryNav } from '@/data/nav';
import { useTrace } from '@/state/TraceProvider';
export function SectionNavigation() {
  const {nav,navigate}=useTrace();
  const group=NAV_GROUPS.find(group=>group.items.some(item=>item.id===primaryNav(nav)));
  if (!group) return null;
  return <div className="workspace-section-bar">
    <span className="workspace-section-label">{group.label}</span>
    <nav aria-label="Разделы рабочей области" className="workspace-section-links">
      {group.items.map(item=><button type="button" key={item.id} aria-current={primaryNav(nav)===item.id?'page':undefined} onClick={()=>navigate(item.id)}>{item.label}</button>)}
    </nav>
  </div>;
}
