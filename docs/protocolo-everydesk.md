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
3. primeira parte = chave do servidor. Em `PunchHoleRequest` uma chave errada mantém a resposta upstream `LICENSE_MISMATCH`, enviada direto na própria conexão (o socket **nunca** entra em `tcp_punch`); em `RequestRelay` nega;
4. `my_id` na allow-list;
5. `pm.get(my_id).pk` existe e verifica a assinatura sobre `ed-punch-v1|my_id|id|ts`;
6. `|agora − ts| ≤ 120 s` (ambos os extremos aceitos; vale também para presença). A
   janela é larga de propósito: um relógio de cliente uns 30–60 s fora (comum em PC
   sem NTP) não pode desligar a máquina em silêncio;
7. o par `(my_id, ts)` não foi aceito nos últimos 300 s (anti-replay em memória,
   TTL ≥ 2× a janela, então um envelope nunca sai do anti-replay enquanto o `ts`
   ainda é aceito). O cliente garante `ts` estritamente crescente por processo.

A assinatura (5) é verificada **antes** da janela (6), então o erro de relógio só
existe para um envelope que o próprio `my_id` assinou.

Falha: o hbbs loga `auth: denied <my_id> -> <target_id> (<motivo>)` e

- relógio fora da janela (assinatura válida) em `PunchHoleRequest`: responde na
  própria conexão `PunchHoleResponse { other_failure: "clock" }` (o socket não
  entra em `tcp_punch`). O cliente deve mostrar algo como "relógio deste computador
  está errado — acerte data/hora" em vez de "offline";
- qualquer outra falha (assinatura ruim, sem envelope, fora da allow-list, replay)
  e toda falha em `RequestRelay`: conexão fechada sem resposta.

O envelope é removido do `RequestRelay` antes de repassá-lo ao alvo.

Vetor de teste conhecido (seed fixa → envelope esperado): `docs/protocolo-everydesk-vector.md`.

## UUID de relay com HMAC (`RELAY_SECRET`)

Com a variável de ambiente `RELAY_SECRET` definida (mesmo valor no hbbs e no hbbr):

- o hbbs reescreve o uuid de relay como `<base>.<tag>`, com
  `tag = base64url_sem_padding(HMAC-SHA256(SHA256(RELAY_SECRET), base))`:
  no `RequestRelay` repassado ao alvo e no `RelayResponse` repassado ao solicitante
  — este só recebe tag se o destino (`socket_addr`) for um socket de solicitante
  que autenticou nos últimos 60 s; caso contrário o uuid passa sem tag. Só sockets
  autenticados entram em `tcp_punch`, que é o único caminho até o solicitante;
- o hbbr emparelha os dois sockets pela `base` e só emparelha se ao menos um deles
  apresentou um uuid com tag válida (o outro lado usa o uuid sem tag que ele mesmo
  gerou). Uuid com `.` e tag inválida é recusado na hora
  (`relay: denied <base> from <addr> (bad uuid hmac)`).

Sem `RELAY_SECRET` (ou vazio) os dois se comportam como upstream. O hbbr sempre
emparelha pela parte antes do primeiro `.`; uuids upstream não têm `.`, então
hbbs com segredo + hbbr sem segredo continua funcionando (sem a proteção). O
contrário (hbbr com segredo, hbbs sem) quebra todo relay — configurar os dois juntos.

## Risco residual: canal hbbs em texto claro

A conexão TCP cliente↔hbbs (porta 21116) não é cifrada neste fluxo (o `secure_tcp`
só roda com token/switch code ou WebRTC). Quem estiver no caminho (on-path) consegue:

- ler o envelope e o uuid com tag enquanto trafegam, e usar o uuid com tag para se
  emparelhar no hbbr antes do lado legítimo (dentro da janela de 30 s do hbbr). O
  relay continua carregando a sessão cifrada ponta a ponta do RustDesk (chaves
  assinadas pelo servidor), então isso dá no máximo negação de serviço ou uso de
  banda, não acesso à sessão;
- reenviar o envelope para o **mesmo** alvo dentro de 120 s, se o original não chegou
  ao hbbs (o anti-replay só bloqueia o que já foi visto);
- descartar ou atrasar mensagens (negação de serviço).

Também resta, igual ao upstream e sem precisar estar no caminho: qualquer um pode
mandar ao hbbs um `RelayResponse` forjado com `socket_addr` de um solicitante que
tem conexão aberta, e o hbbs o entrega por `tcp_punch` (com tag se o solicitante
autenticou nos últimos 60 s). Isso só atrapalha aquela tentativa de conexão (DoS),
porque o par no hbbr ainda exige o outro lado e a sessão continua cifrada ponta a ponta.

Não consegue forjar envelope para outro alvo ou outro ID (a assinatura amarra
`my_id`, alvo e ts), nem obter tag de relay sem antes autenticar.

## Presença (`OnlineRequest`, porta 21115)

O `OnlineRequest` (consulta de quais peers estão online, resposta em bitmap) também
exige o envelope, agora no campo `id`:

```
<server_key>;v1;<my_id>;<unix_ts>;<base64 sig>
```

com `sig` = ed25519 *detached* de `ed-online-v1|<my_id>|<unix_ts>` (domínio
próprio: uma assinatura de punch não vale para presença e vice-versa). O hbbs
(`requester_auth::OnlineGate`), em ordem:

1. no máximo 10 pedidos a cada 5 s por IP de origem (todo pedido conta, válido ou não). A cota é por IP e não 1 porque várias máquinas atrás do mesmo NAT (casa, escritório) compartilham o IP; com mais de ~10 EveryDesk sondando atrás de um NAT, alguns pedidos ficam sem resposta e o app mantém o último estado conhecido;
2. `peers.len() ≤ 200`;
3. envelope `v1` com a chave do servidor;
4. `my_id` na allow-list e com `pk` registrado; assinatura e janela de ±120 s;
5. anti-replay `(my_id, ts)` por 300 s (separado do de punch);
6. no máximo 1 pedido a cada 5 s por `my_id` (só pedidos autenticados contam, então
   um forjador não consome a cota de outro ID).

Falha: conexão fechada sem resposta (inclusive relógio fora da janela: o
`OnlineResponse` não tem campo de erro; o cliente descobre o problema de relógio no
próximo punch); log `online: denied <my_id> (<motivo>)` ou
`online: rate limited <my_id|ip>`. A resposta para quem passa é a mesma de upstream.
Clientes RustDesk comuns deixam de ver presença por este servidor.
