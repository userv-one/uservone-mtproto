# uservone-mtproto

MTProto-прокси на Go. Поддерживает `dd` и fake-TLS (`ee`). Классический режим не поддерживается.

## Возможности

- Прямые подключения к Telegram DC 1–5.
- Secure intermediate с random-padding.
- Fake-TLS handshake и передача данных в TLS records.
- Перенаправление неизвестных клиентов на HTTPS `mask_host`.
- Измерение certificate record реального mask-host.
- Replay-cache и проверка времени handshake.
- Лимиты соединений и idle-таймауты.
- JSON-конфиг, CLI и пакет `core`.

## Сборка

Нужен Go 1.25+.

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" \
  -o dist/uservone-mtproto ./cmd/uservone-mtproto
```

## Настройка

```bash
cp config.example.json config.json
openssl rand -hex 16
```

Укажите секрет в `users.media`. Для fake-TLS задайте реальный HTTPS-домен в `tls_domain` и `mask_host`. Не публикуйте `config.json`.

```bash
./dist/uservone-mtproto -config config.json -check-config
./dist/uservone-mtproto -config config.json
```

Для TLS-only режима установите `"enable_secure": false`. Порт 443 предпочтителен. При `"match_mask_host": true` CLI перед запуском измеряет TLS-ответ mask-host и не стартует при ошибке. Для фиксированной длины задайте `fake_cert_len` и отключите `match_mask_host`.

По умолчанию действуют лимиты 4096 соединений всего, 64 на IP и 600 секунд без чтения. Таймаут продлевается при каждом успешном чтении.

Ссылки для Telegram:

```bash
./dist/uservone-mtproto -config config.json -links-host proxy.example.com
```

Команда выводит секреты. Не отправляйте этот вывод в общие логи.

## Пакет Go

```go
import "github.com/userv-one/uservone-mtproto/core"

cfg := core.DefaultConfig()
cfg.Listen = ":443"
cfg.Users = map[string]string{"media": "32_HEX_SECRET"}
cfg.TLSDomain = "example.com"
cfg.MaskHost = "example.com"

proxy, err := core.New(cfg)
if err != nil {
    return err
}
if cfg.MatchMaskHost && cfg.FakeCertLen == 0 {
    if err := proxy.RefreshMaskProfile(ctx); err != nil {
        return err
    }
}
listener, err := net.Listen("tcp", cfg.Listen)
if err != nil {
    return err
}
return proxy.Serve(ctx, listener)
```

## Docker

```bash
docker build -t uservone-mtproto .
docker run --rm --network host \
  -v "$PWD/config.json:/etc/mtproto/config.json:ro" \
  uservone-mtproto
```

## Проверка

```bash
go test ./...
go test -race ./...
go vet ./...
go test ./core -run FuzzClientHandshakeDoesNotPanic \
  -fuzz=FuzzClientHandshakeDoesNotPanic -fuzztime=5s
go test ./core -run FuzzFakeTLSHelloDoesNotPanic \
  -fuzz=FuzzFakeTLSHelloDoesNotPanic -fuzztime=5s
```

Те же проверки и Docker build запускаются в GitHub Actions.

## Ограничения

- Нет middle-proxy и ad-tag режима.
- Тесты используют локальный эмулятор DC, а не production Telegram.
- Fake-TLS не скрывает IP сервера и не гарантирует обход блокировок.

Источник протокола и закреплённый commit: `PROVENANCE.md`. Настройки безопасности: `SECURITY.md`. SHA-256 артефактов: `dist/SHA256SUMS`.
