# Protocolo EveryDesk v1 — vetor de teste conhecido

Gerado no lado servidor (`src/requester_auth.rs`, teste `known_answer_vector`).
ed25519 é determinístico: um cliente correto, com a mesma seed, produz exatamente
os mesmos envelopes. Se o repositório do cliente tiver o seu próprio vetor, os dois
devem bater byte a byte (mesmas entradas → mesma saída).

## Entradas

| campo | valor |
|---|---|
| seed ed25519 (32 bytes, hex) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| chave do servidor (`server_key`) | `SRVKEY` |
| `my_id` (solicitante) | `123456789` |
| alvo (`target_id`) | `987654321` |
| `ts` (unix, s) | `1800000000` |

## Saídas

pk (base64 padrão, 32 bytes):

```
A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
```

Punch / relay — mensagem assinada e envelope em `licence_key`:

```
ed-punch-v1|123456789|987654321|1800000000
SRVKEY;v1;123456789;1800000000;YJ7AacQGlO9/sFaHhtKSUDdjP5YQrSTDP9k9T7RPIQhAFTsqNfnlwMO1ifWwcnJuUxWEakavEgRpQtYhzbrNBA==
```

Presença — mensagem assinada e envelope em `OnlineRequest.id`:

```
ed-online-v1|123456789|1800000000
SRVKEY;v1;123456789;1800000000;K4o10Ltj36N69t9EPu7drFemTzQtDvuqvoQ1ijCniecHoVbOiG2HWH+u06GbF0EqIkIgNSy+BhA8Wi69QS/6Ag==
```

## O que o servidor verifica com esse vetor

- `check(envelope_punch, "987654321", pk, 1800000000 + 120)` → ok;
- o mesmo com `agora = 1800000121` → `timestamp out of window` (resposta `other_failure = "clock"`);
- o mesmo com alvo `987654322` → `bad signature`;
- `verify_online(envelope_presenca, pk, 1800000000 - 120)` → `123456789`.
