# uservone-media-dc-203

Самостоятельное ядро MTProto-прокси на Go для последующего встраивания в `userv.one`.

## Что реализовано

- `dd` — MTProto secure intermediate с случайным padding; payload передаётся без перепаковки.
- Fake-TLS (`ee`) — проверка ClientHello по HMAC-SHA256, подписанный ServerHello и перенос данных в TLS records.
- Только защищённые транспорты: classic MTProto не поддерживается.
- Маскировка неизвестных клиентов: исходные байты прозрачно пересылаются настоящему HTTPS `mask_host`.
- Ограничение replay для MTProto handshake и fake-TLS ClientHello.
- Проверка времени ClientHello, handshake/connect timeout и строгая валидация конфигурации.
- Прямые подключения к Telegram DC 1–5, включая отрицательные DC index.
- Go API, CLI, Telegram `tg://proxy` ссылки, Docker multi-stage build.
- Никаких сторонних Go-зависимостей.

> Fake-TLS и masking снижают эффективность простых сигнатур и активного сканирования, но не гарантируют обход DPI, блокировок IP или других мер РКН. Для эксплуатации нужен отдельный реальный TLS 1.3 mask-host и собственный домен.

## Сборка и проверка

Требуется Go 1.25 или новее.

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o dist/uservone-media-dc-203 ./cmd/uservone-media-dc-203
```

## Настройка

```bash
cp config.example.json config.json
openssl rand -hex 16
```

Вставьте сгенерированные 32 hex-символа в `users.media`. Замените `tls_domain` и `mask_host` на реальный HTTPS-домен, который вы контролируете или имеете право использовать как mask-host. Не публикуйте `config.json`: он добавлен в `.gitignore`.

Проверка конфигурации:

```bash
./dist/uservone-media-dc-203 -config config.json -check-config
```

Запуск:

```bash
./dist/uservone-media-dc-203 -config config.json
```

Ссылки для Telegram (секреты выводятся только по явной команде):

```bash
./dist/uservone-media-dc-203 -config config.json -links-host proxy.example.com
```

Для TLS-only режима установите `"enable_secure": false`. Для fake-TLS рекомендуется порт 443. `fake_cert_len: 0` выбирает случайную длину ответа при старте процесса; при необходимости её можно зафиксировать значением 1024–65535.

## Встраивание в userv.one

```go
cfg := core.DefaultConfig()
cfg.Listen = ":443"
cfg.Users = map[string]string{"media": "32_HEX_SECRET"}
cfg.TLSDomain = "example.com"
cfg.MaskHost = "example.com"

proxy, err := core.New(cfg)
if err != nil {
    return err
}
listener, err := net.Listen("tcp", cfg.Listen)
if err != nil {
    return err
}
return proxy.Serve(ctx, listener)
```

Импорт пакета: `userv.one/media-dc-203/core`.

## Docker

```bash
docker build -t uservone-media-dc-203 .
docker run --rm --network host \
  -v "$PWD/config.json:/etc/uservone/config.json:ro" \
  uservone-media-dc-203
```

## Границы текущей версии

- Реализован direct mode; рекламные теги и Telegram middle-proxy mode не используются.
- Автоматический подбор длины сертификата с mask-host и ротация IP ещё не реализованы.
- Интеграционные тесты используют эмулятор Telegram DC, а не внешний production DC.
- Исходный протоколный ориентир и закреплённый commit указаны в `PROVENANCE.md`.
- SHA-256 собранных бинарников находится в `dist/SHA256SUMS` после локальной сборки.
