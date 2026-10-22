# Матрица возможностей

«Есть» означает код и ограниченный сценарий, а не промышленную готовность. Доступность бинарников проверяет API modules; фактический результат проверки определяется scannerResults конкретного scan.

| Возможность | Сейчас | Способ реализации / продолжение |
|---|---|---|
| Активы, связи, ответственные | Первый этап | Собственный реестр TRACE; ручной ввод, project association и изолированный импорт инвентаризации |
| Организация, пространства, команды и доступ | Частично — 2А и 2Б.1 реализованы | TRACE: одна организация, workspaces/teams/grants, сессии и scoped service accounts. Scoped settings/env secret_ref реализованы; multi-tenant и SSO впереди |
| SCA | Есть, OSV реально подключён | OSV-Scanner 2.7.0: проверенный binary, реальный фоновый анализ, normalization/dedup/workflow. Trivy/Grype требуют установки. См. 37-connected-engines.md |
| SAST | Есть ограниченно | Встроенный Python AST: четыре правила, реальные локальные запуски, файл/строка, фоновое задание и ручной триаж. Semgrep JSON, atomic batch, Git snapshot CLI/web Job allowlist и execution receipts. Native Semgrep на этой машине блокируется доступом к сертификатам; AST не заменяет dataflow-анализ |
| DAST, безопасность API | HTTP baseline + интеграция ZAP | Реальный один GET к allowlisted loopback HTML и три правила заголовков; сохранение/триаж. ZAP Traditional JSON import. Полное динамическое покрытие и внешние активные проверки не реализованы |
| Поиск секретов | План | Gitleaks/Trivy secret adapter; не сохранять сам секрет в evidence |
| IaC, контейнеры | План | Trivy/Checkov/config adapters; существующий SCA запуск этого не гарантирует |
| SBOM/VEX | Есть ограниченно | TRACE export + Syft/Trivy; нужна привязка к digest/build |
| Лицензии | План | SBOM license ingestion + TRACE policy/review |
| Происхождение, подпись артефактов | Частично | Контекст коммита/digest/deployment, receipt первичного приёма, HMAC delivery history и сверка файлов; Sigstore/cosign/SLSA и асимметричная аттестация впереди |
| PR/CI/CD | Частично | TRACE gate/scan API и подписанный HMAC intake с защитой повторов; PR annotations, автоматические расписания и coverage policy далее |
| Инвентаризация серверов/устройств | Частично | Локальный сборщик и NetBox CLI для выбранной роли серверов, trace.inventory/1, история, актуальность, сравнение и ручная сверка; NetBox проверен на локальном стенде, реальная система не подключена. Cloud/scanner adapters, расписание и корреляция впереди (26–29 этапы) |
| Уязвимости инфраструктуры | План | Импорт из vulnerability scanners, не собственный сетевой сканер |
| Конфигурации, сеть, облако, Kubernetes | План | Cloud APIs, CSPM/KSPM/NDR; normalization в inventory/findings |
| Поверхность атаки | План | ASM integration + scope/ownership evidence |
| Приём/поиск/корреляция событий | План | SIEM integration; отдельный storage/pipeline, не TriageEvent |
| Detection/alerts/threat intelligence | План | SIEM/EDR/NDR/TIP adapters, TRACE связи и workflow |
| Расследования и инциденты | Частично | Собственный TRACE case management, event/detection/incident, ссылки на находки/активы/результаты и история; SIEM и автоматическая корреляция не подключены |
| Управляемое реагирование | План | SOAR/EDR API, только allowlisted actions с approvals/dry-run |
| Идентичности и права | План | IAM/PAM/IdP adapters, TRACE access graph |
| Риски привилегий | План | Аналитика TRACE поверх verified IAM/PAM evidence |
| Управление секретами | План | Vault/secret manager integration, только references |
| Классификация данных/DLP | План | Catalog/DLP adapters, минимум чувствительных данных |
| Риски, политики, исключения | Частично | TRACE gate, finding workflow, ручные risk/task/control и согласование исключения другим admin; автоматическое применение исключений и каталог политик ещё не готовы |
| Требования и доказательства контролей | Частично | Ограниченный compliance report и ручные control records с основаниями/историей; это не аудит соответствия |
| Аудит, отчётность, SLA/KPI | Частично | TriageEvent, actor/scoped platform audit, exports; нужны внешний immutable sink и реальные SLA denominators |

Никаких расчётов «общего процента безопасности» по отсутствующим данным. UI planned-модулей — строки каталога, не пустые рабочие экраны.
Фоновые задания — частично: Job/Attempt/outbox dispatcher, DB admission limits, heartbeat, queued cancel, receipt-based recovery без повторного запуска и операторский retention. Автоматический повтор неопределённого running и расписания не реализованы; см. 09–15 этапы.

Общие результаты модулей — частично: trace.result/1, ручной/подписанный trace.intake/1, workflow/retests, immutable файлы до 64 КиБ и цепочка происхождения. Аттестация истинности отчётов и крупное object storage не реализованы; см. 17–25 этапы.



19 октября 2026, этап 35: SAST подключён к постоянной web Job-очереди через серверный allowlist целей и правил. Добавлены атомарные execution receipts, автоматический приём результатов, повторная авторизация и recovery без повторного сканирования. 8 новых тестов и браузерный путь на изолированном стенде прошли (настоящий Git + явно тестовый процесс). Рабочие 44 таблицы/13 находок сохранены. Настоящий Semgrep отсутствует; рабочий список целей пуст. См. 35-sast-durable-jobs.md.


19 октября 2026, этап 36: добавлено read-only сравнение двух SAST execution receipts и их неизменяемых пакетов. Проверяются хеши и одинаковый контекст; различия rule/path/lines показаны как появившиеся, повторившиеся и больше не наблюдаемые. Исчезновение не считается исправлением; workflow не меняется. 5 новых тестов, TypeScript/build/API-client checks и браузерный сценарий на изолированном стенде прошли. Рабочие 44 таблицы/13 находок сохранены. См. 36-sast-execution-comparison.md.
