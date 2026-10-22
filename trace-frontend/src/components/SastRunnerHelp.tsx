export function SastRunnerHelp({available}:{available:boolean|null}){
  return <section className="panel p-5 space-y-3 min-w-0" style={{overflowWrap:'anywhere'}}><h2>Локальный исполнитель SAST</h2>
    <p>{available===null?'Доступность Semgrep в API ещё не определена.':available?'API обнаружил Semgrep в PATH; успешный запуск этим не подтверждён.':'API не обнаружил Semgrep в PATH. Для локального запуска нужен установленный инструмент.'}</p>
    <p>Операторский CLI остаётся доступен отдельно. Веб-запуск использует только разрешённые сервером цели в блоке «Задания SAST». Просмотр страницы и ручной импорт сами сканер не запускают.</p>
    <details><summary className="cursor-pointer font-semibold">Запуск по закреплённому commit</summary><div className="space-y-3 mt-3"><p>Оператор указывает локальный Git-репозиторий, полный commit, доверенный локальный файл правил, источник appsec и актив «Репозиторий». Исполнитель читает объекты commit во временный каталог; незакоммиченные и untracked-файлы в анализ не включаются. Скрипты проекта не запускаются.</p>
      <code className="block break-all text-xs">.\.venv\Scripts\python.exe tools/run_sast_local.py --repo LOCAL_REPOSITORY --commit FULL_COMMIT_HEX --rules TRUSTED_LOCAL_RULES.yaml --source-id APPSEC_SOURCE_ID --asset-id REPOSITORY_ASSET_ID --run-id UNIQUE_RUN_ID --output-dir NEW_OUTPUT_DIRECTORY</code>
      <p>Из корня trace-core; замените все placeholders. Нужны Git с поддержкой запрета lazy fetch и Semgrep в окружении CLI. Установку и выбор бинарника выполняет оператор. Параметр --timeout ограничивает время сканера, по умолчанию 120 секунд.</p>
      <p>Лимиты: 1000 файлов и 10 МиБ исходников, до 1 МиБ отчёта и 100 результатов. Ошибка, таймаут, неподдерживаемая запись дерева или превышение лимита не считаются успешным анализом. Даже завершённый процесс не подтверждает полное покрытие.</p>
      <p>Проверьте execution.json и manifest.json. Для пакетного импорта выбирайте только manifest.json и finding-*.json — execution.json остаётся локальным журналом исполнения. Он не является подписанной аттестацией и не повышает доверие к импортированному commit.</p>
      <p className="micro">Локальные правила и отключённые метрики не заменяют сетевую изоляцию. Этот режим не является контейнерной песочницей или фоновым планировщиком.</p>
    </div></details>
  </section>;
}
