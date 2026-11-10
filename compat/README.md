# Entitled-record config generator

`uservone-mtproto-config` converts a JSON array of entitled UUID credentials into a JSON file accepted by `core.LoadConfig`.

## Input schema

The top-level value is an array. Each element has exactly these fields:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `uuid` | string | yes | Canonical hyphenated UUID (`8-4-4-4-12` hexadecimal digits). |
| `secret` | string | yes | Exactly 32 hexadecimal characters (16 bytes). |
| `entitled` | boolean | yes | Only `true` records are included. |

Example with a non-production secret:

```json
[
  {
    "uuid": "123e4567-e89b-12d3-a456-426614174000",
    "secret": "42424242424242424242424242424242",
    "entitled": true
  },
  {
    "uuid": "123e4567-e89b-12d3-a456-426614174001",
    "secret": "43434343434343434343434343434343",
    "entitled": false
  }
]
```

Non-entitled records are omitted from the output only after validation. Every array element must be a non-null object with exactly the lowercase field names above; missing or null fields, malformed credentials in any record, and case-variant keys are errors. Duplicate included UUIDs are detected case-insensitively, included UUIDs are stored in lowercase, and an input with no included users is an error. Secrets are never printed to standard output or standard error.

## Command

```sh
uservone-mtproto-config \
  -input entitled.json \
  -output config.json \
  -listen :443 \
  -tls-domain proxy.example.com \
  -mask-host www.example.com
```

`-input` and `-output` are required. `-listen` and `-tls-domain` default to the corresponding core defaults. An omitted `-mask-host` defaults to the selected TLS domain.

The generated configuration enables both secure (`dd`) and fake-TLS (`ee`) transports and HTTPS masking, retains the core safety defaults, and keys `users` by lowercase UUID. The output is written through a temporary file in the destination directory and atomically renamed. Temporary and destination files are created with mode `0600`; existing output is not changed when generation fails.

## Container ownership handoff

The release container runs as UID/GID `65532`, while the generated `0600` configuration is owned by the user who ran the generator. On a Linux Docker host, hand the file to that container user after generation and preserve its private mode:

```sh
sudo chown 65532:65532 config.json
sudo chmod 0600 config.json
```

Repeat the ownership handoff after every regeneration because atomic replacement creates a new file owned by the generating user. A read-only bind mount does not bypass file ownership or permissions.
