import type { Finding, Severity } from '@/data/findings';

const levels: {id:Severity;label:string;color:string}[] = [
  {id:'critical',label:'Критические',color:'#f46c82'},
  {id:'high',label:'Высокие',color:'#eca259'},
  {id:'medium',label:'Средние',color:'#e0c56b'},
  {id:'low',label:'Низкие',color:'#5aa8ec'},
  {id:'unknown',label:'Без оценки',color:'#89929e'},
];

/** Distribution of the selected scan, never a synthetic security score. */
export function SignalProfile({findings,onOpen}:{findings:Finding[];onOpen:()=>void}) {
  let offset=0;
  const total=findings.length;
  return <section className="signal-profile" aria-label="Распределение находок по критичности">
    <div className="signal-profile-label"><span>ПРОФИЛЬ НАХОДОК</span><span>5 УРОВНЕЙ</span></div>
    <div className="signal-orbit">
      <svg viewBox="0 0 300 300" role="img" aria-label={`${total} находок в выбранной проверке`}>
        <circle className="orbit-guide" cx="150" cy="150" r="144" />
        <circle className="orbit-guide" cx="150" cy="150" r="94" />
        <path className="orbit-cross" d="M150 0V44M150 256V300M0 150H44M256 150H300"/>
        <circle className="orbit-track" cx="150" cy="150" r="118" pathLength="100"/>
        {levels.map(level=>{const count=findings.filter(f=>f.severity===level.id).length;const share=total?count/total*100:0;const start=offset;offset+=share;return share>0&&<circle key={level.id} className="orbit-segment" cx="150" cy="150" r="118" pathLength="100" stroke={level.color} strokeDasharray={`${Math.max(share-.9,0.1)} ${100-Math.max(share-.9,0.1)}`} strokeDashoffset={-start}/>;})}
      </svg>
      <button className="orbit-center" onClick={onOpen} aria-label={`Открыть все находки: ${total}`}><span>В ЭТОЙ ПРОВЕРКЕ</span><strong>{total}</strong><span>находок ↗</span></button>
    </div>
    <div className="signal-legend">{levels.map(level=><div key={level.id}><i style={{background:level.color}}/><span>{level.label}</span><strong>{findings.filter(f=>f.severity===level.id).length}</strong></div>)}</div>
    <p>Распределение по критичности. Не оценка защищённости.</p>
  </section>;
}

export function AnalysisMark({kind}:{kind:'cicd'|'sast'|'dast'|'sca'}) {
  const code=kind==='sast'?['source.py','AST → rules','evidence.json']:kind==='sca'?['dependencies','package → advisory','component.json']:kind==='cicd'?['commit','pipeline → policy','release decision']:['authorized target','scope → requests','runtime evidence'];
  return <div className="analysis-mark" aria-hidden="true"><span className="analysis-mark-index">TRACE / {kind.toUpperCase()}</span><div className="analysis-mark-symbol">{kind==='sast'?'‹/›':kind==='sca'?'◈':kind==='cicd'?'↗':'◎'}</div><div className="analysis-mark-lines">{code.map((line,i)=><div key={line}><span>0{i+1}</span><code>{line}</code><i/></div>)}</div><span className="analysis-mark-caption">СХЕМА НАПРАВЛЕНИЯ · НЕ СТАТУС ЗАПУСКА</span></div>;
}
