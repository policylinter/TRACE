import { Children, Fragment, isValidElement, useEffect, useId, useState, type ReactNode, type ReactElement } from 'react';
export function DeckPanel({children}: {id:string;title:ReactNode;children:ReactNode}) {return <>{children}</>;}
function flatten(children:ReactNode):ReactNode[]{return Children.toArray(children).flatMap(child=>isValidElement<{children?:ReactNode}>(child)&&child.type===Fragment?flatten(child.props.children):[child]);}
/** Panels stay mounted: switching sections must not discard unsaved form drafts. */
export function SectionDeck({children}:{children:ReactNode}) {
 const uid=useId();const nodes=flatten(children);
 const panels=nodes.filter((node):node is ReactElement<{id:string;title:ReactNode;children:ReactNode} >=>isValidElement(node)&&node.type===DeckPanel);
 const [selected,setSelected]=useState('');const active=panels.some(p=>p.props.id===selected)?selected:panels[0]?.props.id;
 useEffect(()=>{const open=(event:Event)=>{const target=document.getElementById((event as CustomEvent<string>).detail);const panel=target?.closest('[data-deck-panel]');if(panel){setSelected(panel.getAttribute('data-deck-panel')||'');requestAnimationFrame(()=>target?.scrollIntoView({behavior:'smooth',block:'start'}));}};window.addEventListener('trace:open-section',open);return()=>window.removeEventListener('trace:open-section',open);},[]);
 return <div className="section-deck">{nodes.filter(node=>!isValidElement(node)||node.type!==DeckPanel)}
 {panels.length>1&&<nav className="deck-navigation" aria-label="Подразделы страницы">{panels.map(panel=><button type="button" id={uid+panel.props.id+'-tab'} key={panel.props.id} aria-current={active===panel.props.id?'page':undefined} aria-controls={uid+panel.props.id} onClick={()=>setSelected(panel.props.id)}>{panel.props.title}</button>)}</nav>}
 {panels.map(panel=><div role="region" aria-labelledby={panels.length>1?uid+panel.props.id+'-tab':undefined} id={uid+panel.props.id} data-deck-panel={panel.props.id} hidden={active!==panel.props.id} key={panel.props.id}>{panel.props.children}</div>)}
 </div>;
}
