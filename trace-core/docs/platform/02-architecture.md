# Концепция и целевая архитектура

TRACE объединяет контекст активов, доказательства и работу команды. Специализированные SIEM, EDR, IAM/PAM, DLP и облачные средства остаются источниками и исполнителями; TRACE связывает их данные с ответственными, рисками и исправлениями.

## Модульный монолит
Один FastAPI и одна транзакционная БД. Модули identity, inventory, appsec, infrastructure, monitoring, access-data, governance, integration, workflow. У модуля manifest: id, версия контракта, владелец, capabilities, mode (native/integration/planned), permissions и status. Первый этап даёт read-only каталог модулей, не загрузку произвольных Python-плагинов. Адаптеры используют общие команды и нормализованные envelopes, не записывают напрямую в чужие таблицы.

UI и API используют один доменный слой. Background worker разворачивается отдельно только для долгих задач; текущий Celery пригоден после добавления persisted Job/attempt, heartbeat, lease, cancellation, idempotency key и transactional outbox. Сначала PostgreSQL при появлении конкурентных записей; микросервисы сейчас не нужны.

## Модель данных (целевая, не всё реализовано)
| Область | Сущности и ограничения |
|---|---|
| Доступ | Organization → Workspace → Team, User, Membership(org, workspace, role), ServiceAccount(scopes, expiry), Role/Permission. org_id обязательный во всех бизнес-таблицах, составные FK запрещают связи между организациями. Не брать org_id на доверии из request body. |
| Инвентарь | Asset(org, workspace, kind, external_key, owner, criticality, lifecycle), AssetRelation(source, target, type, evidence_id, observed_at, valid_until). Уникальность org+source+external_key; направление и допустимые типы связей проверяются. |
| Supply chain | Repository → Commit → Build → Artifact(digest, SBOM, VEX, signature) → Deployment(environment, observed_at) → Asset. Не отождествлять теги с immutable digest. |
| Выполнение | Check(scope, policy_version), Job/Attempt(engine, status, started/finished, coverage, error), Engine, Integration, Schedule, WebhookDelivery. Статусы completed, partial, failed, not_configured, not_implemented раздельны. |
| Результаты | Finding — дефект/экспозиция со stable fingerprint и occurrence; SecurityEvent — наблюдение во времени; Detection — срабатывание правила на событиях; Investigation — проверка гипотез; Incident — согласованное нарушение; Risk — оценка вероятности/ущерба и решение. Разные жизненные циклы и связи, без общего объекта «всё есть finding». |
| Доказательства | Evidence(source, raw_ref, hash, collected_at, confidence, method, verifier), DataSource, ChangeHistory. AI assertion хранится отдельно от observation и human verification. «Подтверждено» требует evidence + метод + actor + время, одно численное confidence недостаточно. |
| Работа | Policy/Control(version), Owner, SLA, Task, Exception(expiry, reason), Approval, Remediation, Retest, AuditEvent. Исключение не удаляет находку. |

Цепочка: код → commit → build → artifact digest → deployment/environment → asset → finding или security event → detection/investigation → incident или risk → remediation task → новый check/retest. Каждое ребро имеет источник и время. Первый этап сохраняет Asset/Relation, проект даёт переход к существующим scans/findings; это корреляция по проекту, ещё не доказанная supply chain.

## API, ingestion и безопасность
Версионированные /api/v1 контракты, pagination, лимиты размеров, запросов и tenant quotas. Envelope: schema_version, org, workspace, integration, external_id, observed_at, received_at, object_type, payload_ref, confidence, demo. Вход: проверка подписи webhook + timestamp/replay window; сначала сохранять delivery/outbox, затем нормализация. Idempotency по org+source+external_id; fingerprint finding по engine rule+asset+location/package coordinates, без слияния разных версий. История occurrences остаётся после дедупликации.

Tenant enforcement обязателен и в API, worker, export, webhook, relation и evidence download. Перед включением второго tenant — миграция legacy в явную организацию, deny-by-default, тесты против подмены id/фильтра/ссылок, scoped service accounts. Текущий этап только single-install.

Секреты: БД хранит secret_ref, UI только masked metadata; секрет доступен worker через OS secret store/Vault, без передачи на клиент и записи в audit/logs. Ротация, revoke, scopes, проверка egress allowlist. Админские изменения и чтение evidence — append-only audit с actor/request id; контроль удаления и экспорт в независимый приёмник. Ни один adapter не запускает активное сканирование/реагирование без scope и разрешённой цели.

## Объёмы и хранение
Находки/активы/риски — PostgreSQL, индексы org+status+updated_at, курсорная пагинация. Ориентир MVP: 100 тыс. активов, 1 млн. occurrences; измерять на синтетических данных до обещаний SLA. Evidence blobs — object storage с hash и signed scoped access.

События — отдельный pipeline: batch intake, очередь с backpressure, partition по org/time, retention и replay. Сначала интеграция SIEM с выборочным импортом alerts/evidence refs; не класть весь поток в findings/SQLite. При устойчивых требованиях поиска большого объёма — специализированное хранилище после benchmark. Проектные default retention: raw events 7–30 дней, alerts/incidents 180–365 дней, findings и audit 1 год; это параметры политики организации, с legal hold, purge job и проверкой восстановления. Нужны quotas, lag/drop metrics, DLQ, cold archive, удаление raw и производных данных по одному lifecycle.
