import {SectionDeck,DeckPanel} from '@/components/SectionDeck';
import { useCallback, useEffect, useState, type ReactNode } from 'react';
import {
  gateScan,
  getAdminToken,
  getAiProviders,
  getAuthStatus,
  getMe,
  getPolicySettings,
  getScanPolicy,
  login as apiLogin,
  logout as apiLogout,
  setAdminToken,
  testAi,
  updateAiSettings,
  updatePolicySettings,
  type AiProvidersResponse,
  type AiSettings,
  type AuthStatus,
  type AuthUser,
  type PolicySettings,
} from '@/lib/api';
import { useTrace } from '@/state/TraceProvider';
import { Badge, Micro, PageHeader, Panel } from '@/components/primitives';
import { cx } from '@/lib/format';

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <Micro className="mb-1.5 block">{label}</Micro>
      {children}
      {hint ? <p className="mt-1 text-2xs leading-relaxed text-slate-600">{hint}</p> : null}
    </label>
  );
}

const inputCls =
  'w-full rounded-md border border-hairline bg-ink-950/60 px-2.5 py-1.5 font-mono text-[12px] text-slate-200 outline-none transition-colors focus:border-jade-500/50';

export function AiSettingsPage() {
  const { workspaceId } = useTrace();
  const [data, setData] = useState<AiProvidersResponse | null>(null);
  const [draft, setDraft] = useState<Partial<AiSettings>>({});
  const [modelsText, setModelsText] = useState('');
  const [adminToken, setAdminTokenState] = useState('');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const apply = useCallback((payload: AiProvidersResponse) => {
    setData(payload);
    setDraft(payload.settings);
    setModelsText(payload.settings.models.join('\n'));
  }, []);

  const load = useCallback(async () => {
    try {
      apply(await getAiProviders());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не удалось загрузить настройки ИИ');
    }
  }, [apply]);

  useEffect(() => {
    void load();
    setAdminTokenState(getAdminToken());
  }, [load, workspaceId]);

  const patch = (next: Partial<AiSettings>) => setDraft((d) => ({ ...d, ...next }));

  const collect = (): Partial<AiSettings> => ({
    ...draft,
    models: modelsText
      .split(/[\n,]/)
      .map((m) => m.trim())
      .filter(Boolean),
  });

  const persistToken = () => setAdminToken(adminToken);

  const save = async () => {
    setBusy(true);
    setNote(null);
    setError(null);
    persistToken();
    try {
      const res = await updateAiSettings(collect());
      setData((prev) =>
        prev ? { ...prev, settings: res.settings, active: res.active, available: res.available } : prev,
      );
      setDraft(res.settings);
      setModelsText(res.settings.models.join('\n'));
      setNote(`Сохранено · активный движок: ${res.active}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не удалось сохранить');
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    setNote(null);
    setError(null);
    persistToken();
    try {
      const res = await testAi(collect());
      setNote(
        `${res.ok ? 'OK' : 'Ошибка'} · ${res.provider}${res.model ? `:${res.model}` : ''} · ${res.detail}`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Проверка не прошла');
    } finally {
      setBusy(false);
    }
  };

  const discovered = [...(data?.models.ollama ?? []), ...(data?.models.openai ?? [])];

  return (
    <div className="space-y-3"><SectionDeck>
      <PageHeader
        title="Настройки"
        meta={data ? `активный движок · ${data.active}` : 'загрузка…'}
        right={
          data ? (
            <Badge tone={data.available ? 'positive' : 'neutral'}>
              {data.available ? 'провайдер доступен' : 'rules-движок'}
            </Badge>
          ) : null
        }
      />
      <p className="wb-footnote">Настройки анализа и политик относятся к выбранному рабочему пространству: {data?.settings.workspaceId || workspaceId}.</p>

      {error ? (
        <p role="alert" className="panel px-4 py-2.5 font-mono text-2xs text-rose-300">{error}</p>
      ) : null}
      {note ? (
        <p role="status" className="panel px-4 py-2.5 font-mono text-2xs text-jade-300">{note}</p>
      ) : null}

      <DeckPanel id="AiSettingsPage-1" title={<>ИИ-помощник по уязвимостям</>}><section className="wb-card ai-analysis-settings">
        <div className="wb-card-heading"><div><span className="wb-kicker">КАЧЕСТВО АНАЛИЗА</span><h2>ИИ-помощник по уязвимостям</h2></div><span className="wb-count">{data?.active || 'Загрузка…'}</span></div>
        {data?.active === 'rules' && <p className="analysis-guard">Сейчас активен движок правил. Для ответа нейромодели раскройте «Подключение, модели и доступ», выберите провайдера и проверьте соединение.</p>}
        <p className="wb-footnote">Модель разбирает данные находки и доказательства, отделяет наблюдения от гипотез и предлагает проверки. При отсутствии данных вывод остаётся на ручной проверке.</p>
        <div className="mt-5 grid gap-4 sm:grid-cols-2">
          <Field label="Глубина разбора"><select className={inputCls} value={draft.analysisDepth ?? 'deep'} onChange={e=>patch({analysisDepth:e.target.value as 'standard'|'deep'})}><option value="deep">Глубокий: условия, влияние, пробелы, план проверки</option><option value="standard">Краткий: основные выводы и недостающие данные</option></select></Field>
          <Field label="Язык ответа"><select className={inputCls} value={draft.responseLanguage ?? 'ru'} onChange={e=>patch({responseLanguage:e.target.value as 'ru'|'en'})}><option value="ru">Русский</option><option value="en">English</option></select></Field>
        </div>
        <div className="mt-4"><Field label="Контекст проекта и развёртывания" hint="Например: сервис доступен из интернета, выполняется под отдельной учётной записью, принимает файлы. Контекст оператора отмечается как непроверенный; он не заменяет доказательства."><textarea maxLength={4000} rows={3} className={inputCls} value={draft.analystContext ?? ''} onChange={e=>patch({analystContext:e.target.value})} placeholder="Как используется приложение и что известно об окружении…"/></Field></div>
        <label className="mt-4 flex items-start gap-3 text-sm"><input type="checkbox" checked={draft.reviewPass ?? false} onChange={e=>patch({reviewPass:e.target.checked})}/><span>Повторная проверка ответа<span className="block mt-1 text-xs text-slate-500">При одной модели добавляется второй проход. Это увеличивает время анализа и не считается независимым подтверждением.</span></span></label>
        <div className="ai-capability-grid"><div><strong>Доказательства</strong><p>Наблюдения с идентификаторами шагов и данных отчёта.</p></div><div><strong>Неопределённость</strong><p>Допущения, условия эксплуатации и недостающие материалы.</p></div><div><strong>Исправление</strong><p>Действия, обоснование и ожидаемый результат проверки.</p></div></div>
        <div className="flex flex-wrap items-center gap-3 mt-5"><button type="button" className="btn-primary" disabled={busy || !data} onClick={save}>{busy?'Обработка…':'Сохранить настройки анализа'}</button><button type="button" className="btn" onClick={()=>{const section=document.getElementById('ai-connection');if(section instanceof HTMLDetailsElement){section.open=true;window.dispatchEvent(new CustomEvent('trace:open-section',{detail:'ai-connection'}));}}}>Подключение модели ↓</button></div>
        <p className="wb-footnote">Для существующей находки откройте её карточку → «Глубокий анализ ИИ». Изменение настроек не запускает анализ автоматически.</p>
      </section></DeckPanel>
      <DeckPanel id="AiSettingsPage-2" title={<>Подключение, модели и доступ</>}><details open className="panel p-4" id="ai-connection"><summary className="settings-section-summary">Подключение, модели и доступ<span>Параметры провайдера</span></summary>
      <div className="grid gap-3 xl:grid-cols-[1.4fr_1fr]">
        <Panel className="p-4">
          <Micro className="mb-3 block">Движок анализа</Micro>
          <div className="space-y-3">
            <Field label="Провайдер" hint={data?.providers.find((p) => p.id === `ai.${draft.provider}`)?.knob}>
              <select
                className={inputCls}
                value={draft.provider ?? 'auto'}
                onChange={(e) => patch({ provider: e.target.value })}
              >
                {(data?.catalog ?? []).map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.label}
                  </option>
                ))}
              </select>
            </Field>

            <Field
              label="Модели (каскад, по одной в строке)"
              hint="Первая модель выдаёт вердикт, каждая следующая перепроверяет предыдущий."
            >
              <textarea
                className={cx(inputCls, 'h-24 resize-y leading-relaxed')}
                value={modelsText}
                onChange={(e) => setModelsText(e.target.value)}
                spellCheck={false}
              />
            </Field>

            {discovered.length > 0 ? (
              <div>
                <Micro className="mb-1.5 block">Обнаруженные модели</Micro>
                <div className="flex flex-wrap gap-1.5">
                  {discovered.map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() =>
                        setModelsText((t) => (t.split(/[\n,]/).map((x) => x.trim()).filter(Boolean).includes(m) ? t : `${t.trim()}\n${m}`.trim()))
                      }
                      className="rounded border border-hairline bg-ink-800/40 px-1.5 py-0.5 font-mono text-2xs text-slate-300 hover:border-jade-500/40 hover:text-jade-200"
                    >
                      + {m}
                    </button>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Ollama URL" hint="Адрес сервера Ollama, на котором выполняется обработка.">
                <input
                  className={inputCls}
                  value={draft.ollamaUrl ?? ''}
                  onChange={(e) => patch({ ollamaUrl: e.target.value })}
                  spellCheck={false}
                />
              </Field>
              <Field label="OpenAI-совместимый base URL" hint="Метаданные находки и доказательства передаются на этот endpoint.">
                <input
                  className={inputCls}
                  value={draft.baseUrl ?? ''}
                  onChange={(e) => patch({ baseUrl: e.target.value })}
                  placeholder="https://api.deepseek.com/v1"
                  spellCheck={false}
                />
              </Field>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Ссылка на секрет" hint={draft.secretRef ? (draft.secretRefReady ? 'Секрет доступен процессу API. Доступность у worker проверяется при запуске.' : 'Ссылка сохранена; секрет в окружении API не найден.') : (draft.apiKeySet ? 'Используется прежний ключ основной установки. Новые ключи задаются через ссылку.' : 'Секрет не задан.')}>
                <input
                  className={inputCls}
                  value={draft.secretRef ?? ''}
                  onChange={(e) => patch({ secretRef: e.target.value })}
                  placeholder="env:AI_KEY"
                  spellCheck={false}
                />
              </Field>
              <Field label="Temperature">
                <input
                  type="number"
                  step="0.05"
                  min="0"
                  max="1"
                  className={inputCls}
                  value={draft.temperature ?? 0.1}
                  onChange={(e) => patch({ temperature: Number(e.target.value) })}
                />
              </Field>
              <Field label="Timeout, с">
                <input
                  type="number"
                  step="5"
                  min="5"
                  className={inputCls}
                  value={draft.timeout ?? 90}
                  onChange={(e) => patch({ timeout: Number(e.target.value) })}
                />
              </Field>
            </div>
            <p className="wb-footnote">Укажите имя ссылки, затем оператор задаст значение в окружении API и worker. Сам ключ в TRACE не вводится. {data?.settings.secretEnvironmentName && <>Переменная сервера: <code className="break-all">{data.settings.secretEnvironmentName}</code>.</>}</p>

            <Field
              label="Admin-токен / Bearer"
              hint="Статический X-Admin-Token либо bearer из входа (RBAC)."
            >
              <input
                type="password"
                className={inputCls}
                value={adminToken}
                onChange={(e) => setAdminTokenState(e.target.value)}
                spellCheck={false}
              />
            </Field>

            <AuthPanel token={adminToken} onToken={setAdminTokenState} />

            <div className="flex flex-wrap gap-2 pt-1">
              <button type="button" onClick={save} disabled={busy} className="btn-primary">
                Сохранить
              </button>
              <button type="button" onClick={test} disabled={busy} className="btn-ghost">
                Проверить соединение
              </button>
              <button type="button" onClick={() => void load()} disabled={busy} className="btn-ghost">
                Сбросить
              </button>
            </div>
          </div>
        </Panel>

        <Panel className="p-4">
          <Micro className="mb-3 block">Провайдеры</Micro>
          <ul className="space-y-2">
            {(data?.providers ?? []).map((p) => (
              <li key={p.id} className="rounded-md border border-hairline bg-ink-950/40 p-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[12px] text-slate-200">{p.label}</span>
                  <Badge tone={p.available ? 'positive' : 'neutral'}>
                    {p.available ? 'online' : 'offline'}
                  </Badge>
                </div>
                <p className="mt-1 break-all font-mono text-2xs text-slate-500">{p.detail}</p>
                {p.install ? <p className="mt-1 text-2xs text-slate-600">{p.install}</p> : null}
              </li>
            ))}
          </ul>
          <p className="mt-3 text-2xs leading-relaxed text-slate-600">
            Выбор сохраняется в БД и применяется к новым сканам и пересчётам. Ключи API не
            возвращаются наружу — только маска. При указании внешнего endpoint данные находки и доказательства передаются на этот адрес:
            включайте осознанно.
          </p>
        </Panel>
      </div>

      </details></DeckPanel>
      <DeckPanel id="AiSettingsPage-3" title={<>Политика релиза и управление проектами</>}><details open className="panel p-4"><summary className="settings-section-summary">Политика релиза и управление проектами<span>Администрирование</span></summary><div className="mt-4 space-y-4"><PolicyPanel /><ProjectsPanel /></div></details></DeckPanel>
    </SectionDeck></div>
  );
}

function ProjectsPanel() {
  const { projects, projectId, setProject, removeProject } = useTrace();
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const handleDelete = async (id: number, name: string, scanCount: number) => {
    if (
      !window.confirm(
        `Удалить проект «${name}» вместе с ${scanCount} сканами и их находками? Действие необратимо.`,
      )
    )
      return;
    setBusy(id);
    setError(null);
    setNote(null);
    try {
      await removeProject(id);
      setNote(`Проект удалён: ${name}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не удалось удалить проект');
    } finally {
      setBusy(null);
    }
  };

  return (
    <Panel className="p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <Micro className="block">Рабочие области (проекты)</Micro>
        <span className="font-mono text-2xs text-slate-500">{projects.length}</span>
      </div>

      <ul className="divide-y divide-hairline">
        {projects.map((project) => {
          const active = project.id === projectId;
          const deletable = project.id !== 1;
          return (
            <li key={project.id} className="flex items-center gap-3 py-2.5">
              <button
                type="button"
                onClick={() => setProject(project.id)}
                className={cx(
                  'flex min-w-0 flex-1 items-center gap-3 text-left',
                  active ? 'text-jade-200' : 'text-slate-300 hover:text-slate-100',
                )}
              >
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-hairline-strong bg-ink-800 font-mono text-2xs font-semibold text-slate-300">
                  {project.name.slice(0, 2).toUpperCase()}
                </span>
                <span className="flex min-w-0 flex-col">
                  <span className="truncate font-mono text-[12px]">{project.name}</span>
                  <span className="truncate font-mono text-2xs text-slate-500">
                    {project.repoUrl || 'без remote-url'} · {project.scanCount} сканов
                  </span>
                </span>
                {active ? <Badge tone="accent">активный</Badge> : null}
              </button>
              {deletable ? (
                <button
                  type="button"
                  disabled={busy === project.id}
                  onClick={() => void handleDelete(project.id, project.name, project.scanCount)}
                  className="shrink-0 rounded border border-hairline px-2 py-1 font-mono text-2xs text-rose-300 transition-colors hover:border-rose-400/40 hover:bg-rose-500/10 disabled:opacity-40"
                >
                  {busy === project.id ? 'удаляю…' : 'удалить'}
                </button>
              ) : (
                <span className="shrink-0 font-mono text-2xs text-slate-600">защищён</span>
              )}
            </li>
          );
        })}
      </ul>

      {error ? <p className="mt-3 font-mono text-2xs text-rose-300">{error}</p> : null}
      {note ? <p className="mt-3 font-mono text-2xs text-jade-300">{note}</p> : null}
      <p className="mt-3 text-2xs leading-relaxed text-slate-600">
        Удаление проекта убирает и все его сканы с находками. Проект по умолчанию (с демо-сканом)
        защищён.
      </p>
    </Panel>
  );
}

function AuthPanel({ token, onToken }: { token: string; onToken: (value: string) => void }) {
  const trace = useTrace();
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const refreshMe = useCallback(async () => {
    try {
      const me = await getMe();
      setUser(me.authenticated ? me.user ?? null : null);
    } catch {
      setUser(null);
    }
  }, []);

  useEffect(() => {
    getAuthStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
    void refreshMe();
  }, [refreshMe]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    setNote(null);
    try {
      const res = await apiLogin(username, password);
      if (res.token) {
        setAdminToken(res.token);
        onToken(res.token);
        setUser(res.user);
        await trace.refreshAuth();
        await trace.reload();
        setNote(`Вход выполнен: ${res.user?.username} (${res.user?.role})`);
      } else {
        setNote('RBAC выключен — используется статический токен');
      }
      setPassword('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не удалось войти');
    } finally {
      setBusy(false);
    }
  };

  const doLogout = async () => {
    setBusy(true);
    try {
      await trace.signOut();
      setAdminToken('');
      onToken('');
      setUser(null);
      setNote('Сессия завершена');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не удалось выйти');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-md border border-hairline bg-ink-950/40 p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <Micro>Доступ</Micro>
        {status ? (
          <Badge tone={status.enabled ? 'accent' : 'neutral'}>
            {status.enabled ? `RBAC · ${status.method}` : 'открытый доступ'}
          </Badge>
        ) : null}
      </div>

      {user ? (
        <div className="flex items-center justify-between gap-2">
          <span className="font-mono text-2xs text-slate-300">
            {user.displayName} · <span className="text-jade-300">{user.role}</span>
          </span>
          <button type="button" onClick={doLogout} disabled={busy} className="btn-ghost">
            Выйти
          </button>
        </div>
      ) : status?.enabled ? (
        <div className="space-y-2">
          <input
            className={inputCls}
            placeholder="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            spellCheck={false}
          />
          <input
            className={inputCls}
            type="password"
            placeholder="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            spellCheck={false}
          />
          <button type="button" onClick={submit} disabled={busy || !username || !password} className="btn-primary">
            Войти
          </button>
        </div>
      ) : (
        <p className="text-2xs leading-relaxed text-slate-500">
          RBAC выключен. Запросы к админским эндпоинтам авторизуются статическим токеном
          (поле «Admin-токен / Bearer» выше). Включается переменной <code className="text-slate-400">TRACE_AUTH_ENABLED=1</code>.
        </p>
      )}

      {token && !user ? (
        <p className="mt-2 font-mono text-2xs text-slate-600">токен задан вручную ({token.slice(0, 6)}…)</p>
      ) : null}
      {error ? <p className="mt-2 font-mono text-2xs text-rose-300">{error}</p> : null}
      {note ? <p className="mt-2 font-mono text-2xs text-jade-300">{note}</p> : null}
    </div>
  );
}

function PolicyPanel() {
  const { activeScanId, scan } = useTrace();
  const [policy, setPolicy] = useState<PolicySettings | null>(null);
  const [exemptions, setExemptions] = useState('');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [gate, setGate] = useState<Awaited<ReturnType<typeof getScanPolicy>> | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await getPolicySettings();
      setPolicy(res.policy);
      setExemptions((res.policy.exemptions ?? []).join('\n'));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не удалось загрузить политику');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!activeScanId) return;
    getScanPolicy(activeScanId)
      .then(setGate)
      .catch(() => setGate(null));
  }, [activeScanId]);

  const toggleSeverity = (severity: string) => {
    setPolicy((p) =>
      p
        ? { ...p, blockOn: p.blockOn.includes(severity) ? p.blockOn.filter((s) => s !== severity) : [...p.blockOn, severity] }
        : p,
    );
  };

  const save = async () => {
    if (!policy) return;
    setBusy(true);
    setNote(null);
    setError(null);
    try {
      const res = await updatePolicySettings({
        ...policy,
        exemptions: exemptions.split(/[\n,]/).map((e) => e.trim()).filter(Boolean),
      });
      setPolicy(res.policy);
      setNote(`Политика сохранена: ${res.policy.name}`);
      if (activeScanId) setGate(await gateScan(activeScanId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не удалось сохранить политику');
    } finally {
      setBusy(false);
    }
  };

  const severities = [
    ['critical', 'critical'],
    ['high', 'high'],
    ['medium', 'medium'],
    ['low', 'low'],
  ] as const;

  return (
    <Panel className="p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Micro className="block">Политика релиза и CI-гейт</Micro>
          {policy ? <Badge tone="positive">{policy.name}</Badge> : null}
        </div>
        {gate ? (
          <Badge tone={gate.gate === 'blocked' ? 'negative' : 'positive'}>
            gate: {gate.gate} · exit {gate.exitCode}
          </Badge>
        ) : null}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-3">
          <div>
            <Micro className="mb-1.5 block">Блокировать релиз при вердикте «affected» на высоте:</Micro>
            <div className="flex flex-wrap gap-1.5">
              {severities.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => toggleSeverity(value)}
                  className={cx(
                    'rounded border px-2 py-1 font-mono text-2xs transition-colors',
                    policy?.blockOn.includes(value)
                      ? 'border-rose-400/40 bg-rose-500/10 text-rose-200'
                      : 'border-hairline bg-ink-800/40 text-slate-400 hover:border-hairline-strong',
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <label className="block">
            <Micro className="mb-1.5 block">Исключения (CVE, по одной в строке)</Micro>
            <textarea
              className={cx(inputCls, 'h-24 resize-y leading-relaxed')}
              value={exemptions}
              onChange={(e) => setExemptions(e.target.value)}
              placeholder={'CVE-2021-44228'}
              spellCheck={false}
            />
          </label>

          <label className="flex cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              checked={policy?.warnOnReview ?? true}
              onChange={(e) => setPolicy((p) => (p ? { ...p, warnOnReview: e.target.checked } : p))}
              className="h-3.5 w-3.5 accent-jade-500"
            />
            <span className="text-2xs text-slate-400">Варнить «reachable но не проверено» (needs_review)</span>
          </label>

          <div className="flex flex-wrap gap-2 pt-1">
            <button type="button" onClick={save} disabled={busy} className="btn-primary">
              Сохранить политику
            </button>
            <button
              type="button"
              disabled={busy || !activeScanId}
              className="btn-ghost"
              onClick={() => activeScanId && gateScan(activeScanId).then(setGate).catch((e) => setError(String(e)))}
            >
              Пересчитать гейт
            </button>
          </div>
        </div>

        <div className="space-y-2">
          <Micro className="block">Результат гейта для {scan ? `${scan.repository}@${scan.commit}` : 'активного скана'}</Micro>
          {gate ? (
            <>
              <div
                className={cx(
                  'rounded-md border px-3 py-2 font-mono text-2xs',
                  gate.gate === 'blocked'
                    ? 'border-rose-400/40 bg-rose-500/10 text-rose-200'
                    : 'border-jade-500/40 bg-jade-500/10 text-jade-200',
                )}
              >
                {gate.gate.toUpperCase()} · exit code {gate.exitCode}
                <span className="ml-2 text-slate-500">
                  block {gate.summary.blocking} · warn {gate.summary.warnings} · pass {gate.summary.passed} · из{' '}
                  {gate.summary.total}
                </span>
              </div>
              <ul className="space-y-1">
                {gate.blocking.map((b) => (
                  <li key={b.cve} className="flex items-center gap-2 font-mono text-2xs text-slate-400">
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-rose-400" />
                    <span className="text-rose-200">{b.cve}</span>
                    <span className="truncate">{b.packageName}</span>
                    <Badge tone="negative">{b.severity}</Badge>
                  </li>
                ))}
                {gate.blocking.length === 0 && gate.summary.blocking === 0 ? (
                  <li className="font-mono text-2xs text-slate-500">блокирующих нет — гейт открыт</li>
                ) : null}
              </ul>
              <div className="mt-2 rounded-md border border-hairline bg-ink-950/60 p-2.5">
                <Micro className="mb-1 block">Вызов в CI</Micro>
                <code className="block break-all font-mono text-2xs leading-relaxed text-slate-400">
                  curl -sf -X POST "http://127.0.0.1:8000/api/v1/scans/{gate.scanId}/gate?enforce=1"
                </code>
                <p className="mt-1 text-2xs text-slate-600">
                  enforce=1 вернёт HTTP 409 при блокировке и уронит пайплайн; без него gate всегда 200,
                  а решение — в поле exitCode.
                </p>
              </div>
            </>
          ) : (
            <p className="text-2xs text-slate-500">Пересчитайте гейт или дождитесь активного скана.</p>
          )}
        </div>
      </div>
    </Panel>
  );
}
