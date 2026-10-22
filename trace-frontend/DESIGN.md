# TRACE — визуальная система

Обновление 21 октября 2026. Общие стили: src/premium.css; структура разделов: src/data/nav.ts; контекстные вкладки: src/components/SectionNavigation.tsx.

Навигация разделена на рабочее пространство, безопасность разработки, аналитику и администрирование. Все прежние маршруты сохранены. Контекст сканирования доступен в раскрываемом блоке меню. VEX и соответствие стандартам имеют отдельные пункты. Активное состояние раздела и вложенного экрана задаётся aria-current.

Графитовая боковая панель сохраняет характер в обеих темах. Светлая тема использует белые поверхности, серо-зелёный фон и глубокий зелёный акцент; тёмная — приглушённые зелёно-графитовые поверхности. Общие правила распространяются на карточки, таблицы, формы, кнопки, вкладки, уведомления полноты и метрики. Цвета серьёзности угроз остаются семантическими.

Предусмотрены перенос вкладок, мобильные отступы, сохранение горизонтального скролла широких таблиц, focus-visible и prefers-reduced-motion. Шрифты системные, без внешних запросов.

Проверено: tsc --noEmit, production build (97 модулей), 7 API-client checks, SSR/семантические smoke-тесты и live VEX 13/13. Сервер на 5173 отдаёт новые JS/CSS и отвечает health. Первоначально браузерная проверка была заблокирована служебной страницей. Позднее пользователь открыл рабочую вкладку, и проверка выполнена; подробности ниже.


## Уточнение композиции и браузерная проверка

На обзоре добавлен реальный следующий шаг по очереди приоритетов. В карточке находки вкладки подняты выше дополнительного AI-разбора, provenance и связанные рабочие записи перенесены в соответствующий контекст. В таблице доступны включение/скрытие четырёх дополнительных столбцов и плотность строк с сохранением в localStorage; закреплены заголовки при прокрутке таблицы.

Блокировка браузера разрешилась после открытия пользователем рабочей вкладки. Проверены обзор при узком viewport и desktop 1440×900, переход по приоритетной находке, вкладки исправления/команды, сохранение скрытого столбца после reload и обратное включение. Ошибок консоли при проверке не получено. Повторно прошли TypeScript, build, 7 API-client checks и smoke с live VEX 13/13. Временный desktop viewport сброшен.


## Завершение общего редизайна — 21 октября 2026

- Администрирование: 5 подразделов доступа (организация, участники, сервисные аккаунты, retention, аудит), 3 подраздела пространств/команд/разрешений, 3 подраздела настроек. SectionDeck сохраняет смонтированные формы и черновики при переключении; скрытые панели исключаются из отображения и accessibility tree.
- DevSecOps: собственные подразделы CI/CD, SAST и SCA; отдельное честное состояние DAST. Описание SAST актуализировано. Статус инструмента не выдаётся за результат его работы.
- Активы: реестр, инвентаризация, источники/импорт и модули. Регистрация раскрывается по запросу. Переход из инвентаризации к активу открывает реестр с подробностями.
- Общая система оформления распространена на каталоги проектов, карточки, граф зависимостей, отчёты, заголовки, формы, таблицы, пустые состояния, сообщения ошибок/успеха и диалоги. Экран входа оформлен как отдельная композиция; auth не переключался ради проверки дизайна.
- Командная палитра берёт маршруты из общего реестра; сочетания клавиш используют единый KEYBOARD_NAV. Точные совпадения разделов идут перед общим поиском в триаже. Переход к организации через Enter проверен. Ошибка копирования VEX отображается явно.

Проверки: TypeScript и production build (98 модулей); 7 API-client checks; SSR/семантические smoke и live VEX 13/13. В браузере открыты все 18 основных разделов в тёмной и светлой темах на desktop; все 18 — в светлой теме на 390×844. У страницы нет горизонтального переполнения, широкие таблицы имеют внутренний скролл. Проверены 23 внутренних вкладки и 4 раздела активов. Финальная проверка 23 панелей: ровно одна видимая, содержимое присутствует. Черновик настроек сохраняется между вкладками; тестовый текст восстановлен без сохранения на сервер. Диалог команд открывается/закрывается Escape, поиск и Enter работают; ошибок консоли не получено. Тёмная тема восстановлена, временный viewport сброшен.

Артефакты: C:/Users/vlad/Documents/Codex/2026-10-17/files-pasted-by-the-user-trace/outputs/TRACE-redesign-checks.json, TRACE-full-access-dark.png, TRACE-full-settings-light.png.

Границы проверки: не выполнялась каждая административная операция с изменением прав/удалением данных; экран входа собран, но визуально через включение обязательного входа не проверялся. Готовность внешних сканеров и интеграций описана в backend-документации отдельно от готовности интерфейса.
# Lab7 direction — 22 October 2026

The user selected [Cybersecurity Dashboard by Lab7](https://www.behance.net/gallery/229362849/Cybersecurity-Dashboard) as the visual reference. The active stylesheet is now `src/lab7.css`; `studio.css` is not imported. Deep navy surfaces, blue controls, restrained semantic statuses and dense tables replace the previous lime and marketing composition. Existing explicit light-theme preferences are retained; new sessions default to dark.

Overview is an operational dashboard: severity cards, a seven-item priority table, recent checks and a contextual rail for distribution, release policy and scanner status. Every count uses the selected scan's stored data; no invented trend, security score or live telemetry is shown. Unknown severity remains visible in the distribution legend. Demo and coverage warnings remain visible. The finding links, triage CTA and scan selection remain functional. Direction pages show their actual context instead of decorative illustrations, with loading/error states.

Validation: production build, TypeScript and smoke checks passed. Browser layout checks covered 18 routes in dark and light at 1440px, and light at 390px (54 checks), with no document overflow. A separate dark-mobile overview inspection passed. Opening a priority finding was verified. No console errors observed. These are UI checks, not a certification of external scanner availability.

## Previous direction (superseded)

# Signal Studio — 21 October 2026

The active visual direction is graphite, cool silver and lime. `src/studio.css`, loaded after the existing workspace styles, defines the current tokens and shared component treatment for both themes. It includes reduced-motion support and responsive composition.

The overview has a new two-column command composition. `SignalProfile` draws a severity distribution from the selected scan's findings, with a button into the findings queue; it is not a security score. Demo and coverage notices remain visible below the overview hero. DevSecOps directions use a distinct `AnalysisMark` composition, explicitly labelled as a diagram rather than execution status. Existing controls, forms and backend contracts are retained.

Validation: TypeScript and production build passed; smoke checks passed. Browser navigation exercised all 18 sections at 1440px in dark and light themes, and 390px in light theme (54 layout checks); no document-level horizontal overflow or console errors observed. The default 329px viewport was restored and also checked on the overview. This is layout verification, not certification of every backend operation.

