# Переход с Python mtprotoproxy

Документ описывает контракт для `uservone-platform`. Сами JS-файлы в этом репозитории отсутствуют, поэтому здесь заданы требования к интеграции, а не результат их изменения.

## Режимы

| Python | Go JSON | Примечание |
|---|---|---|
| `PORT` | `listen` | Адрес и порт, например `:443` |
| `USERS` | `users` | Имя или UUID → 32 hex-символа |
| `MODES.classic` | не поддерживается | Должно быть `false` |
| `MODES.secure` | `enable_secure` | `dd` |
| `MODES.tls` | `enable_tls` | `ee` |
| `TLS_DOMAIN` | `tls_domain` | ASCII host name |
| `MASK_HOST`, `MASK_PORT` | `mask_host`, `mask_port` | HTTPS mask-host |
| `USE_MIDDLE_PROXY` | `use_middle_proxy` | `true` требует Python |
| `AD_TAG` | `ad_tag` | Непустой tag требует Python |

Go-реализация работает только в direct mode. При `USE_MIDDLE_PROXY=true` или заданном `AD_TAG` нельзя удалять эти настройки и продолжать с Go: поведение рекламы и маршрутизации изменится. Конфигурация должна быть отклонена, а платформа должна остаться на Python.

Python AST inspector больше не нужен для Go-конфигурации. JSON decoder отклоняет неизвестные поля, неправильные типы, небезопасные секреты и неподдерживаемый middle-proxy режим.

## Генератор

`uservone-mtproto-config` принимает список UUID с секретами и признаком `entitled`. Схема и пример без реального секрета: `compat/README.md`.

```bash
uservone-mtproto-config \
  -input entitled.json \
  -output config.json \
  -tls-domain proxy.example.com \
  -mask-host www.example.com \
  -listen :443
```

Выходной файл создаётся с режимом `0600`. Секреты не печатаются в stdout или логи.

Форматы ссылок не меняются:

- `dd`: `dd || 16-byte secret`, hex в query `secret`.
- `ee`: `ee || 16-byte secret || ASCII TLS domain`, hex в query `secret`.
- Остальные query-параметры: `server` и `port`.

Для получения машинного списка используется `uservone-mtproto -config config.json -links-host proxy.example.com -format json`.

## Rotation

По `SIGHUP` процесс перечитывает JSON. Новые секреты начинают приниматься сразу. Прежние остаются приниматься в течение `rotation_grace_seconds` (по умолчанию 300) и затем удаляются. Уже установленные соединения не разрываются. Ошибка чтения или проверки нового файла оставляет прежний набор без изменений. Секреты в логах не выводятся.

## Feature flag

Рекомендуемый флаг платформы: `MTPROTO_IMPL=python|go`.

Начальное значение для существующих узлов — `python`. `go` включается только для direct-mode узлов без `AD_TAG`. Нельзя менять флаг автоматически при обновлении пакета.

## Изменения в uservone-platform

- `server/mtprotoConfig.js`: для `go` вызывать генератор JSON; для `python` сохранять существующий writer `config.py`, включая `USE_MIDDLE_PROXY` и `AD_TAG`.
- `server/ssh.js`: задавать `MTPROTO_DIR` и systemd `ExecStart` по флагу. Go: `uservone-mtproto -config /etc/uservone-mtproto/config.json`. Python: прежний `python3 mtprotoproxy.py config.py`. Секреты не передавать аргументами командной строки.
- `server/nodeHealth.js`: учитывать выбранную реализацию и отдельно сообщать ошибку конфигурации, процесса и health endpoint.
- `server/mtprotoHealth.js`: для Go читать `/health`; для Python оставить прежнюю проверку. TCP listen без handshake не считать доказательством работоспособности.
- `server/mtprotoRemoteProbe.js`: проверять выбранные `dd`/`ee` handshake. Не подменять результат простым DNS или TCP success.
- `server/telegramProxies.js`: принимать JSON links от Go CLI; не разбирать человекочитаемый лог.
- `server/mtprotoCredentials.js`: использовать тот же 16-byte secret и те же правила `dd`/`ee`; не добавлять префикс дважды.

## Rollback на Python

1. Установить `MTPROTO_IMPL=python`.
2. Восстановить прежний `config.py`, включая `USERS`, `USE_MIDDLE_PROXY` и `AD_TAG`.
3. Вернуть прежние `MTPROTO_DIR` и systemd `ExecStart`.
4. Остановить Go unit и запустить Python unit.
5. Повторить remote handshake probe.

Откат перезапускает процесс и разрывает его активные TCP-соединения. Grace period относится только к rotation внутри запущенного Go-процесса, а не к смене реализации.
