import {SectionDeck,DeckPanel} from '@/components/SectionDeck';
import {SastJobsPanel} from '@/components/SastJobsPanel';
import {SastRunnerHelp} from '@/components/SastRunnerHelp';
import {SastResultsPanel} from '@/components/SastResultsPanel';
import {useEffect,useState} from 'react';
import {useTrace} from '@/state/TraceProvider';
import {platformModules,getResultSources,getScanPolicy,type ResultSource,type GateResult} from '@/lib/api';
import {SourceWebhookPanel} from '@/components/SourceWebhookPanel';
import {DastBaselinePanel} from '@/components/DastBaselinePanel';

export type DevelopmentView='cicd'|'sast'|'dast'|'sca';
const titles:Record<DevelopmentView,string>={cicd:'CI/CD',sast:'SAST — анализ исходного кода',dast:'DAST — динамический анализ',sca:'SCA — анализ зависимостей'};
const descriptions:Record<DevelopmentView,string>={
  cicd:'Подписанная доставка отчётов и оценка по текущей release policy. Внешний pipeline подключается отдельно.',
  sast:'Управляйте локальными заданиями, импортом отчётов и результатами Semgrep. Возможность запуска зависит от проверенного движка и разрешённых сервером целей.',
  dast:'Локальная HTTP-проверка трёх заголовков и импорт ZAP Traditional JSON. Разбирайте наблюдения и назначайте исправления; полное динамическое покрытие этими проверками не подтверждается.',
  sca:'Состояние Trivy, Grype и OSV-Scanner и сведения об их выполнении в выбранной проверке.'};
const labels:Record<string,string>={completed:'Завершено',partial:'Частично',failed:'Ошибка',error:'Ошибка',skipped:'Пропущено',not_configured:'Не настроен',not_implemented:'Не реализовано',running:'Выполняется',queued:'В очереди',ok:'Успешно',pass:'Пропуск разрешён',fail:'Пропуск заблокирован',warn:'Предупреждение',blocked:'Пропуск заблокирован',passed:'Пропуск разрешён',warning:'Предупреждение'};
const label=(value:string)=>labels[value]||value;

export function DevSecOpsPage({view}:{view:DevelopmentView}) {
  const t=useTrace();const [sastRevision,setSastRevision]=useState(0);
  const [engines,setEngines]=useState<{id:string;label:string;available:boolean}[]>([]);
  const [sources,setSources]=useState<ResultSource[]>([]);
  const [policy,setPolicy]=useState<GateResult|null>(null);
  const [error,setError]=useState('');const [loading,setLoading]=useState(true);const [revision,setRevision]=useState(0);
  const scan=t.scan?.id===t.activeScanId?t.scan:null;
  const scanId=scan?.id;
  useEffect(()=>{
    let live=true;setLoading(true);setError('');setEngines([]);setSources([]);setPolicy(null);
    async function load(){
      try {
        if(view==='cicd'){
          const values=await Promise.all([getResultSources(),scanId?getScanPolicy(scanId):Promise.resolve(null)]);
          if(live){setSources(values[0]);setPolicy(values[1]);}
        } else if(view!=='dast'){
          const modules=await platformModules();
          if(live)setEngines((modules.modules.find(m=>m.id==='appsec')?.engines||[]).filter(e=>view==='sast'?['scanner.semgrep','scanner.python-ast'].includes(e.id):['scanner.trivy','scanner.grype','scanner.osv'].includes(e.id)));
        }
      }catch(e){if(live)setError(e instanceof Error?e.message:String(e));}
      finally{if(live)setLoading(false);}
    }
    void load();return()=>{live=false;};
  },[view,t.workspaceId,scanId,revision]);
  const results=(scan?.scannerResults||[]).filter(r=>r.role===view);
  const currentPolicy=policy?.scanId===scanId?policy:null;
  const admin=!t.auth?.enabled||t.user?.role==='admin';
  return <div className={`development-workspace development-${view} space-y-4`}><SectionDeck>
    <section className="panel p-5 space-y-3 direction-hero"><div className="direction-hero-copy">
      <p className="eyebrow">Безопасность разработки / {view==='cicd'?'Доставка':view.toUpperCase()}</p><h1 className="text-lg font-semibold">{titles[view]}</h1><p>{descriptions[view]}</p>
      <nav aria-label="Направления DevSecOps" className="flex flex-wrap gap-2">{(['cicd','sast','dast','sca'] as const).map(id=><button key={id} className="btn" aria-current={view===id?'page':undefined} onClick={()=>t.navigate(id)}>{id==='cicd'?'CI/CD':id.toUpperCase()}</button>)}</nav>
      <p className="micro">Рабочее пространство: {t.workspaces.find(w=>w.id===t.workspaceId)?.name||t.workspaceId}. Наличие инструмента в PATH не подтверждает его запуск или покрытие.</p>
      {view!=='dast'&&<button className="btn" disabled={loading} onClick={()=>setRevision(n=>n+1)}>Обновить состояние направления</button>}
      {loading&&<p role="status">Загрузка состояния…</p>}{error&&<p role="alert" className="text-rose-300">{error}</p>}
    </div><aside className="module-summary"><span>КОНТЕКСТ НАПРАВЛЕНИЯ</span><strong>{view.toUpperCase()}</strong><p>{loading?'Загрузка состояния…':error?'Состояние недоступно':view==='dast'?'HTTP baseline + импорт ZAP':view==='cicd'?`${sources.length} источников доставки`:`${engines.filter(e=>e.available).length} из ${engines.length} движков доступны`}</p><p>Выбранная проверка</p><code>{scan?.id||'Не выбрана'}</code><button className="btn" onClick={()=>t.navigate('scans')}>Открыть проверки ↗</button></aside></section>
    {view==='sast'&&<section className="panel p-5 space-y-3"><h2>Встроенная проверка Python</h2><p>Четыре AST-правила: eval/exec, pickle/dill, yaml.load и shell=True. Исходный код не выполняется. Другие языки и потоки данных этим движком не проверяются; наблюдения требуют ручного разбора.</p><button className="btn-primary" onClick={()=>t.navigate('scans')}>Открыть запуск по локальному пути</button><p className="micro">Результаты сохраняются в выбранной проверке и общей очереди AppSec. Этот движок независим от Semgrep.</p></section>}
    {view==='sast'&&<DeckPanel id="DevSecOpsPage-1" title={"Запуски SAST"}><SastJobsPanel key={t.workspaceId} onChanged={()=>setSastRevision(n=>n+1)}/></DeckPanel>}
    {view==='dast'&&<DastBaselinePanel/>}
    {view==='cicd'&&<section className="panel p-5 space-y-3"><h2>SCA-проверка в pipeline</h2><p>В репозитории TRACE есть исполняемый gate: tools/run_sca_ci.py и шаблон .gitlab-ci.example.yml. Шаблон запускает OSV закреплённой версии, проверяет SHA-256 и сохраняет osv.json и gate.json.</p><p>Коды завершения: 0 — порог политики не превышен при наличии покрытия пакетов; 1 — есть блокирующие находки; 2 — ошибка движка, отчёта или отсутствие покрытия. Неизвестная серьёзность не пропускается молча.</p><p className="micro">Внешний GitLab runner подключается отдельно. Наличие шаблона не подтверждает запуск pipeline в вашем GitLab. Для подписанной доставки результатов используйте настройки источников ниже.</p></section>}
    {view==='sast'&&<DeckPanel id="DevSecOpsPage-2" title={"Подключение движка"}><SastRunnerHelp available={loading||!!error?null:engines.some(e=>e.id==='scanner.semgrep'&&e.available)}/></DeckPanel>}
    {view==='sast'&&<DeckPanel id="DevSecOpsPage-3" title={"Результаты SAST"}><SastResultsPanel key={t.workspaceId+sastRevision}/></DeckPanel>}
    {view==='dast'?<DeckPanel id="DevSecOpsPage-4" title={<>Отчёты ZAP</>}><section className="panel p-5 space-y-3"><h2>Импорт и разбор DAST</h2><p>Поддерживается Traditional JSON ZAP: сайт, правило, URL и HTTP-метод. Параметры URL и фрагменты не сохраняются; тела запросов и атакующие значения не импортируются.</p><button className="btn-primary" onClick={()=>t.navigate('scans')}>Импортировать отчёт ZAP</button><h3>Выбранная проверка: {scan?.id||'не выбрана'}</h3>{results.length?results.map(r=><article key={r.id}><h3>{r.label} · {r.status==='imported'?'Отчёт импортирован':label(r.status)}</h3><p>{r.detail}</p></article>):<p>В выбранной проверке нет отчёта ZAP. Общие AppSec-находки не считаются DAST-результатами.</p>}<button className="btn" disabled={!results.length} onClick={()=>t.navigate('findings')}>Открыть находки выбранной проверки</button><p className="micro">Активное сканирование требует отдельного исполнителя, разрешённой цели и лимитов. Импорт не подтверждает полноту проверки или эксплуатацию.</p></section></DeckPanel>:<>
      <DeckPanel id="DevSecOpsPage-5" title={<>Контекст проверки</>}><section className="panel p-5 space-y-3"><h2>Контекст проверки</h2>
        <label className="field-label block">Проверка для просмотра<select className="trace-select block w-full min-w-0 max-w-full" value={t.activeScanId||''} onChange={e=>t.setActiveScan(e.target.value)} disabled={!t.scans.length}><option value="" disabled>Выберите проверку</option>{t.scans.map(s=><option key={s.id} value={s.id}>{s.repository} · {s.branch} · {s.id}</option>)}</select></label>
        {scan?<><p className="break-all">{scan.repository} · {scan.branch} · {scan.id}</p><p>Статус всей проверки: {label(scan.status)}. {scan.id==='scan-8f21a3c'?'Демонстрационная проверка.':''}</p></>:<p>Проверка не выбрана. Статистику анализа пока показать нельзя.</p>}
        {t.error&&<p role="alert" className="text-rose-300">Не удалось загрузить рабочие данные: {t.error}</p>}
        <div className="flex flex-wrap gap-2"><button className="btn" onClick={()=>t.navigate('scans')}>Запуски и история проверок</button>{view==='sca'&&<button className="btn" disabled={!scan} onClick={()=>t.navigate('sbom')}>Зависимости и SBOM</button>}<button className="btn" disabled={!scan} onClick={()=>t.navigate('findings')}>Общая очередь AppSec</button></div>
        <p className="micro">Запуск через общий контур проверок может задействовать несколько доступных движков. Здесь не заявляется отдельное выполнение только выбранного направления.</p>
      </section></DeckPanel>
      {view!=='cicd'?<>
        <DeckPanel id="DevSecOpsPage-6" title={<>Инструменты на сервере сейчас</>}><section className="panel p-5 space-y-3"><h2>Инструменты на сервере сейчас</h2>{!loading&&!error&&!engines.length&&<p>API не вернул сведения об инструментах этого направления.</p>}{engines.map(e=><p key={e.id}><strong>{e.label}</strong> · {e.available?'Обнаружен в PATH; выполнение не подтверждено':'Не обнаружен в PATH'}</p>)}</section></DeckPanel>
        <DeckPanel id="DevSecOpsPage-7" title={<>Выполнение в выбранной проверке</>}><section className="panel p-5 space-y-3"><h2>Выполнение в выбранной проверке</h2>{!results.length?<p>Для этого направления нет отдельных записей выполнения. Статус всей проверки и количество общих находок не подтверждают успешный {view.toUpperCase()}-анализ.</p>:results.map(r=><article key={r.id}><h3>{r.label} · {label(r.status)}</h3><p className="break-words">{r.detail||'Подробности не переданы'}</p></article>)}{view==='sast'&&<p className="micro">Результаты Semgrep могут использоваться как свидетельства достижимости. Отсутствие отдельной SAST-находки не означает отсутствия проблем в коде.</p>}</section></DeckPanel>
      </>:<>
        <DeckPanel id="DevSecOpsPage-8" title={<>Оценка по текущей release policy</>}><section className="panel p-5 space-y-3"><h2>Оценка по текущей release policy</h2>{currentPolicy?<><p>Решение: {label(currentPolicy.gate)} · exit code {currentPolicy.exitCode}</p><p>Блокирующих: {currentPolicy.summary.blocking}; предупреждений: {currentPolicy.summary.warnings}; рассмотрено: {currentPolicy.summary.total}.</p><p className="micro">Оценка вычислена для указанных находок по текущим настройкам. Историческое решение CI и факт развёртывания этим не подтверждаются.</p></>:!loading&&!error&&<p>Нет выбранной проверки для просмотра оценки.</p>}<button className="btn" onClick={()=>t.navigate('settings')}>Настройки политики</button></section></DeckPanel>
        <DeckPanel id="DevSecOpsPage-9" title={<>Источники подписанной доставки</>}><section className="panel p-5 space-y-3"><h2>Источники подписанной доставки</h2><p>Источники выбранного пространства. Регистрация и включение приёма сами по себе не означают подключение pipeline.</p>{!loading&&!error&&!sources.length&&<p>Источники ещё не зарегистрированы.</p>}{sources.map(s=><article key={s.id}><h3>{s.name}</h3><p>{s.module} · {s.active?'Приём разрешён':'Приём выключен'}</p>{admin?<SourceWebhookPanel sourceId={s.id}/>:<p className="micro">Настройки подписанного приёма доступны администратору.</p>}</article>)}<button className="btn" onClick={()=>t.navigate('platform')}>Регистрация источников и импорт отчётов</button></section></DeckPanel>
      </>}
    </>}
  </SectionDeck></div>;
}
