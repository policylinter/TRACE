import { downloadFile } from '@/lib/format';
import { useEffect, useId, useMemo, useRef, useState, type PointerEvent } from 'react';
import { useTrace } from '@/state/TraceProvider';
import { IconGraph, IconLayers, IconSearch, IconTarget, IconChevronRight } from '@/components/icons';
import { EmptyState } from '@/components/primitives';
function DependencyGraph() {
    const t = useTrace();
    const host = useRef<HTMLDivElement>(null);
    const id = useId().replace(/:/g, '');
    const [size, setSize] = useState({ w: 1000, h: 580 });
    const [query, setQuery] = useState('');
    const [selected, setSelected] = useState<string | null>(null);
    const [riskOnly, setRiskOnly] = useState(false);
    const [focus, setFocus] = useState(false);
    const [camera, setCamera] = useState({ x: 0, y: 0, scale: 1 });
    const [dragging, setDragging] = useState(false);
    const drag = useRef<{
        x: number;
        y: number;
        cx: number;
        cy: number;
    } | null>(null);
    useEffect(() => { if (!host.current)
        return; const observer = new ResizeObserver(([entry]) => setSize({ w: entry.contentRect.width, h: entry.contentRect.height })); observer.observe(host.current); return () => observer.disconnect(); }, []);
    useEffect(() => { setSelected(null); setFocus(false); }, [t.scan?.id]);
    const focusId = focus ? selected : null;
    const graph = useMemo(() => {
        const all = t.sbom?.nodes || [];
        const edges = t.sbom?.edges || [];
        const keep = new Set<string>();
        all.filter(n => (!riskOnly || n.vulnerable) && (!query || `${n.id} ${n.label}`.toLowerCase().includes(query.toLowerCase())) && (!focusId || n.id === focusId)).forEach(n => keep.add(n.id));
        let changed = true;
        while (changed) {
            changed = false;
            for (const e of edges)
                if (keep.has(e.target) && !keep.has(e.source)) {
                    keep.add(e.source);
                    changed = true;
                }
        }
        const visible = all.filter(n => keep.has(n.id));
        const layers = new Map<number, typeof visible>();
        for (const n of visible) {
            const level = Math.max(0, n.depth || 0);
            layers.set(level, [...(layers.get(level) || []), n]);
        }
        const height = Math.max(380, ...[...layers.values()].map(v => v.length * 98 + 90));
        const width = Math.max(600, ...[...layers.keys()].map(d => d * 302 + 310));
        const nodes = [...layers].flatMap(([depth, list]) => list.map((n, row) => ({ ...n, x: 40 + depth * 302, y: (row + 1) * height / (list.length + 1) - 33 })));
        return { nodes, edges: edges.filter(e => keep.has(e.source) && keep.has(e.target)), width, height };
    }, [t.sbom, query, riskOnly, focusId]);
    const nodeMap = useMemo(() => new Map(graph.nodes.map(n => [n.id, n])), [graph.nodes]);
    function fit() {
      const availableWidth = size.w - (selected && size.w > 800 ? 305 : 0);
      const scale = Math.max(.08, Math.min((availableWidth - 70) / graph.width, (size.h - 85) / graph.height, 1.25));
      setCamera({x: graph.width / 2 - availableWidth / (2 * scale), y: graph.height / 2 - size.h / (2 * scale), scale});
    }
    useEffect(() => { fit(); }, [graph, size.w, size.h, selected]);
    const ancestors = useMemo(() => { const ids = new Set<string>(); if (!selected)
        return ids; ids.add(selected); let changed = true; while (changed) {
        changed = false;
        for (const e of graph.edges)
            if (ids.has(e.target) && !ids.has(e.source)) {
                ids.add(e.source);
                changed = true;
            }
    } return ids; }, [graph, selected]);
    const node = nodeMap.get(selected || '');
    const findings = node ? t.findings.filter(f => node.findingIds?.includes(f.id) || f.packageName === node.id) : [];
    function zoom(factor: number) { setCamera(c => { const scale = Math.max(.08, Math.min(2.5, c.scale * factor)); return { scale, x: c.x + size.w / (2 * c.scale) - size.w / (2 * scale), y: c.y + size.h / (2 * c.scale) - size.h / (2 * scale) }; }); }
    function down(e: PointerEvent<SVGSVGElement>) { if ((e.target as Element).closest('[data-graph-node]'))
        return; e.currentTarget.setPointerCapture(e.pointerId); drag.current = { x: e.clientX, y: e.clientY, cx: camera.x, cy: camera.y }; setDragging(true); }
    function move(e: PointerEvent<SVGSVGElement>) { const d = drag.current; if (d)
        setCamera(c => ({ ...c, x: d.cx - (e.clientX - d.x) / c.scale, y: d.cy - (e.clientY - d.y) / c.scale })); }
    function up() { drag.current = null; setDragging(false); }
    if (!t.sbom)
        return <section className="wb-card wb-empty"><IconGraph className="mx-auto mb-4 h-8 w-8"/><h1>Карта пока не построена</h1><p className="my-4">Откройте проверку с результатами анализа зависимостей.</p><button className="wb-button wb-primary" onClick={() => t.navigate('scans')}>К проверкам →</button></section>;
    return <div className="graph-workspace"><header className="portfolio-heading"><div><span className="wb-kicker">ИССЛЕДОВАНИЕ ЗАВИСИМОСТЕЙ</span><h1>Карта зависимостей<span className="heading-dot">.</span></h1><p>От репозитория до конкретного пакета. Выберите узел для исследования.</p></div><span className="graph-repo-label"><IconLayers className="h-4 w-4"/>{t.scan?.repository}</span></header>
 <section className="graph-studio"><div className="graph-studio-bar"><label className="graph-search"><IconSearch className="h-4 w-4"/><input aria-label="Найти компонент" placeholder="Найти компонент…" value={query} onChange={e => setQuery(e.target.value)}/><kbd>/</kbd></label><div className="graph-mode-toggle"><button aria-pressed={!riskOnly} onClick={() => setRiskOnly(false)}>Все компоненты</button><button aria-pressed={riskOnly} onClick={() => setRiskOnly(true)}>С уязвимостями</button></div><span className="graph-node-count">{graph.nodes.length} узлов · {graph.edges.length} связей</span></div>
 <div className="graph-viewport" ref={host}>
  {!graph.nodes.length && <div className="graph-empty">Компоненты не найдены. Измените поиск или фильтр.</div>}
  <svg width="100%" height="100%" viewBox={`${camera.x} ${camera.y} ${size.w / camera.scale} ${size.h / camera.scale}`} role="group" tabIndex={0} aria-label="Интерактивная карта зависимостей" onKeyDown={e => {
      if (e.target !== e.currentTarget || !['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.key)) return;
      e.preventDefault();
      setCamera(c => ({...c,x:c.x+(e.key==='ArrowLeft'?-60:e.key==='ArrowRight'?60:0)/c.scale,y:c.y+(e.key==='ArrowUp'?-60:e.key==='ArrowDown'?60:0)/c.scale}));
    }} onPointerDown={down} onPointerMove={move} onPointerUp={up} onPointerCancel={up} style={{ cursor: dragging ? 'grabbing' : 'grab', touchAction: 'none' }}>
   <defs><pattern id={`dots-${id}`} width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r=".8" fill="var(--graph-dot)"/></pattern><marker id={`arrow-${id}`} markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0 0 L7 3.5 L0 7" fill="var(--graph-edge)"/></marker><filter id={`node-shadow-${id}`} x="-20%" y="-40%" width="140%" height="180%"><feDropShadow dx="0" dy="3" stdDeviation="6" floodColor="#000" floodOpacity=".2"/></filter></defs>
   <rect x={camera.x} y={camera.y} width={size.w / camera.scale} height={size.h / camera.scale} fill={`url(#dots-${id})`}/>
   {graph.edges.map((e, i) => { const a = nodeMap.get(e.source), b = nodeMap.get(e.target); if (!a || !b)
        return null; const highlighted = selected && ancestors.has(a.id) && ancestors.has(b.id); return <path key={i} d={`M${a.x + 242} ${a.y + 34} C${a.x + 280} ${a.y + 34},${b.x - 38} ${b.y + 34},${b.x} ${b.y + 34}`} fill="none" stroke={highlighted ? 'var(--graph-highlight)' : 'var(--graph-edge)'} strokeWidth={highlighted ? 2.7 : 1.4} opacity={selected && !highlighted ? 0.2 : 1} markerEnd={`url(#arrow-${id})`}/>; })}
   {graph.nodes.map(n => <g key={n.id} data-graph-node="true" transform={`translate(${n.x},${n.y})`} role="button" tabIndex={0} aria-label={`Компонент ${n.id}`} aria-pressed={n.id === selected} onClick={() => setSelected(n.id)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setSelected(n.id);
        } }} style={{ cursor: 'pointer' }} opacity={selected && !ancestors.has(n.id) ? 0.35 : 1}>
    <rect width="242" height="69" rx="10" fill={n.id === selected ? 'var(--graph-selected)' : n.depth === 0 ? 'var(--graph-root)' : 'var(--graph-node)'} stroke={n.id === selected ? 'var(--graph-highlight)' : n.vulnerable ? 'var(--graph-risk-border)' : 'var(--graph-border)'} strokeWidth={n.id === selected ? 2 : 1} filter={`url(#node-shadow-${id})`}/>
    <rect x="12" y="15" width="28" height="28" rx="7" fill={n.vulnerable ? 'var(--danger-soft)' : 'var(--accent-soft)'}/><path d="M20 24 l6 -4 6 4 -6 4z M20 28 l6 4 6 -4" stroke={n.vulnerable ? 'var(--danger)' : 'var(--accent)'} strokeWidth="1.2" fill="none"/>
    <text x="51" y="27" fill="var(--ink)" fontSize="11" fontWeight="550" fontFamily="system-ui">{(n.label || n.id).length > 24 ? (n.label || n.id).slice(0, 23) + '…' : n.label || n.id}</text>
    <text x="51" y="47" fill={n.vulnerable ? 'var(--danger)' : 'var(--muted)'} fontSize="9" fontFamily="system-ui">{n.depth === 0 ? 'REPOSITORY' : n.vulnerable ? `${n.findings} находок · компонент` : 'Компонент зависимости'}</text><circle cx="227" cy="16" r="3" fill={n.vulnerable ? 'var(--danger)' : 'var(--muted)'}/><title>{n.id}</title>
   </g>)}
  </svg>
  <div className="graph-legend"><span><i style={{ background: 'var(--accent)' }}/>Репозиторий</span><span><i style={{ background: 'var(--danger)' }}/>Есть находки</span></div>
  <div className="graph-minimap"><span>НАВИГАТОР</span><svg viewBox={`0 0 ${graph.width} ${graph.height}`} onClick={e => { const box = e.currentTarget.getBoundingClientRect(); const x = (e.clientX - box.left) / box.width * graph.width, y = (e.clientY - box.top) / box.height * graph.height; setCamera(c => ({ ...c, x: x - size.w / (2 * c.scale), y: y - size.h / (2 * c.scale) })); }} aria-label="Миникарта графа">{graph.nodes.map(n => <rect key={n.id} x={n.x} y={n.y} width="242" height="69" rx="10" fill={n.vulnerable ? 'var(--danger)' : 'var(--muted)'}/>)}<rect x={camera.x} y={camera.y} width={size.w / camera.scale} height={size.h / camera.scale} fill="var(--accent-soft)" stroke="var(--accent)" strokeWidth="12"/></svg></div>
  <div className="graph-camera-controls"><button aria-label="Уменьшить граф" onClick={() => zoom(1 / 1.25)}>−</button><span>{Math.round(camera.scale * 100)}%</span><button aria-label="Увеличить граф" onClick={() => zoom(1.25)}>+</button><i /><button onClick={fit}>Вписать</button><button onClick={() => { setSelected(null); setFocus(false); setQuery(''); setRiskOnly(false); fit(); }}>Сброс</button></div>
  {node && <aside className="graph-inspector"><div className="graph-inspector-top"><span className="wb-kicker">ИНСПЕКТОР УЗЛА</span><button aria-label="Закрыть инспектор" onClick={() => { setSelected(null); setFocus(false); }}>×</button></div><span className="inspector-icon"><IconLayers className="h-5 w-5"/></span><h2>{node.id}</h2><div className="inspector-meta"><span>Уровень {node.depth}</span><span>{findings.length} находок</span></div><button className="wb-button" onClick={() => setFocus(v => !v)}><IconTarget className="h-4 w-4"/>{focus ? 'Показать весь граф' : 'Оставить путь к узлу'}</button><h3>Связанные находки</h3>{findings.map(f => <button key={f.id} className="inspector-finding" onClick={() => { t.navigate('findings'); t.select(f.id); }}><div><strong>{f.cve}</strong><span>CVSS {f.cvss} · {f.severity}</span></div><IconChevronRight className="h-4 w-4"/></button>)}{!findings.length && <p className="wb-footnote">Связанные находки в этой проверке отсутствуют.</p>}<p className="wb-footnote">Связи означают зависимости пакетов. Путь исполнения исследуется в доказательствах находки.</p></aside>}
 </div><footer className="graph-studio-footer"><span><i /> {t.scan?.branch} · {t.scan?.commit || 'без коммита'}</span><span>Перетаскивайте фон для перемещения · выберите узел для подробностей</span></footer></section></div>;
}

export function SbomPage() {
 const t = useTrace();
 const [view, setView] = useState<'table' | 'graph'>('table');
 const [query, setQuery] = useState('');
 const [riskOnly, setRiskOnly] = useState(false);
 const [selectedId, setSelectedId] = useState<string | null>(null);
 useEffect(() => {setSelectedId(null);setQuery('');}, [t.scan?.id]);
 const nodes = (t.sbom?.nodes ?? []).filter(n => n.depth > 0);
 const visible = nodes.filter(n => (!riskOnly || n.vulnerable) && `${n.id} ${n.label}`.toLowerCase().includes(query.toLowerCase()));
 const selected = nodes.find(n => n.id === selectedId);
 const related = selected ? t.findings.filter(f => selected.findingIds?.includes(f.id) || f.packageName === selected.id) : [];
 return <div className="space-y-5">
 <header className="page-heading"><div><p className="eyebrow">Состав приложения</p><h1>Зависимости</h1><p>Компоненты, связанные уязвимости и структура зависимостей.</p></div><button className="btn" disabled={!t.sbom} onClick={() => t.sbom && downloadFile(`trace-sbom-${t.scan?.id ?? 'scan'}.json`, JSON.stringify(t.sbom, null, 2), 'application/json')}>Экспорт SBOM JSON</button></header>
 <nav className="section-navigation" aria-label="Представление зависимостей"><button aria-current={view === 'table' ? 'page' : undefined} onClick={() => setView('table')}>Компоненты · {nodes.length}</button><button aria-current={view === 'graph' ? 'page' : undefined} onClick={() => setView('graph')}>Граф связей</button></nav>
 {view === 'graph' ? <DependencyGraph/> : <section className="panel overflow-hidden"><div className="component-toolbar"><input aria-label="Поиск компонентов" placeholder="Название или идентификатор компонента…" value={query} onChange={e => setQuery(e.target.value)}/><label><input type="checkbox" checked={riskOnly} onChange={e => setRiskOnly(e.target.checked)}/>С уязвимостями</label><span className="text-xs">{visible.length} из {nodes.length}</span></div>
 <div className="overflow-x-auto"><table className="component-table"><thead><tr><th scope="col">Компонент</th><th scope="col">Тип</th><th scope="col">Глубина</th><th scope="col">Находки</th><th scope="col">Зависимости</th></tr></thead><tbody>{visible.map(n => <tr key={n.id}><td><button onClick={() => setSelectedId(n.id)} aria-expanded={selectedId === n.id}><code>{n.label || n.id}</code></button></td><td>{n.kind || 'Не указан'}</td><td>{n.depth === 1 ? 'Прямая' : `Транзитивная · ${n.depth}`}</td><td>{n.findings ?? 0}</td><td>{t.sbom?.edges.filter(e => e.source === n.id).length ?? 0}</td></tr>)}</tbody></table></div>
 {!visible.length && <EmptyState icon={<IconLayers className="h-5 w-5" />} title={!t.sbom ? 'Нет данных SBOM' : 'Компоненты не найдены'} description={!t.sbom ? 'Выберите проверку с анализом зависимостей.' : 'Измените поиск или фильтр по уязвимостям.'} />}
 {selected && <section className="component-detail" aria-label="Подробности компонента"><div className="flex justify-between gap-4"><h2>{selected.label || selected.id}</h2><button className="btn" onClick={() => setSelectedId(null)}>Закрыть</button></div><p>Идентификатор: <code>{selected.id}</code></p><p>Версии и экосистемы из связанных находок: {[...new Set(related.map(f => `${f.ecosystem} · ${f.version}`))].join(', ') || 'API графа не передаёт эти сведения.'}</p><div className="component-detail-links">{related.map(f => <button className="btn" key={f.id} onClick={() => {t.navigate('findings');t.select(f.id);}}>{f.cve} →</button>)}</div>{!related.length && <p>Связанных находок нет. Это не подтверждает отсутствие уязвимостей.</p>}</section>}
 </section>}
 </div>;
}
