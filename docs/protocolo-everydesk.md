# Protocolo EveryDesk — autenticação do solicitante (v1)

Este fork exige que quem pede uma conexão (punch ou relay) prove quem é. Clientes
RustDesk comuns são recusados com `auth: denied` no log do hbbs.

## Envelope em `licence_key`

O cliente EveryDesk põe no campo `licence_key` de `PunchHoleRequest` e do
`RequestRelay` enviado ao **hbbs**:

```
<server_key>;v1;<my_id>;<unix_ts>;<base64 sig>
```

- `server_key`: a chave pública do servidor (o mesmo valor que antes ia sozinho no campo; vazio se o servidor roda sem chave).
- `v1`: versão do formato.
- `my_id`: ID EveryDesk do solicitante.
- `unix_ts`: segundos Unix (UTC) no momento do envio.
- `sig`: base64 padrão (com `=`) da assinatura ed25519 *detached* de
  `ed-punch-v1|<my_id>|<target_id>|<unix_ts>`, feita com o par de chaves do
  próprio cliente (`Config::get_key_pair()`, o mesmo `pk` que ele registra no hbbs via `RegisterPk`).

O `RequestRelay` enviado ao **hbbr** continua levando só a chave do servidor (sem envelope).

## Verificação no hbbs (`src/requester_auth.rs`)

Para `PunchHoleRequest` e `RequestRelay`, em ordem:

1. alvo (`id`) na allow-list (como antes);
2. `licence_key` tem 5 partes separadas por `;` e a segunda é `v1` — senão nega;
3. primeira parte = chave do servidor. Em `PunchHoleRequest` uma chave errada mantém a resposta upstream `LICENSE_MISMATCH`; em `RequestRelay` nega;
4. `my_id` na allow-list;
5. `pm.get(my_id).pk` existe e verifica a assinatura sobre `ed-punch-v1|my_id|id|ts`;
6. `|agora − ts| ≤ 30 s`;
7. o par `(my_id, ts)` não foi aceito nos últimos 60 s (anti-replay em memória). O cliente garante `ts` estritamente crescente por processo.

Falha: a conexão TCP é fechada sem resposta e o hbbs loga
`auth: denied <my_id> -> <target_id> (<motivo>)`. O envelope é removido do
`RequestRelay` antes de repassá-lo ao alvo.

## UUID de relay com HMAC (`RELAY_SECRET`)

Com a variável de ambiente `RELAY_SECRET` definida (mesmo valor no hbbs e no hbbr):

- o hbbs reescreve o uuid de relay como `<base>.<tag>`, com
  `tag = base64url_sem_padding(HMAC-SHA256(SHA256(RELAY_SECRET), base))`:
  no `RequestRelay` repassado ao alvo e no `RelayResponse` repassado ao solicitante
  (este só chega a sockets que já passaram na autenticação acima);
- o hbbr emparelha os dois sockets pela `base` e só emparelha se ao menos um deles
  apresentou um uuid com tag válida (o outro lado usa o uuid sem tag que ele mesmo
  gerou). Uuid com `.` e tag inválida é recusado na hora
  (`relay: denied <base> from <addr> (bad uuid hmac)`).

Sem `RELAY_SECRET` (ou vazio) os dois se comportam como upstream. O hbbr sempre
emparelha pela parte antes do primeiro `.`; uuids upstream não têm `.`, então
hbbs com segredo + hbbr sem segredo continua funcionando (sem a proteção). O
contrário (hbbr com segredo, hbbs sem) quebra todo relay — configurar os dois juntos.
