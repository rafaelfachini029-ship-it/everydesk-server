# Painel de aprovação (everydesk-admin)

Painel web para aprovar, bloquear e remover máquinas da allow-list do hbbs.

- URL: https://everydesk.vpsfachini.online (login por senha única).
- Pendentes: quando o hbbs nega um `RegisterPk` por falta na allow-list, ele anexa `<id> <unix_ts> <ip_origem>` em `PENDING_FILE` (`/var/lib/rustdesk-server/pending.txt`, sem duplicatas, máx. 500 linhas). O painel mostra o IP na coluna "Origem (IP)" e aceita também linhas antigas `<id> <unix_ts>` (mostra `-`). O IP ajuda a distinguir uma máquina real de um ID inventado por terceiros.
- Aprovar ID (formulário no topo da página): aprova um ID digitado à mão, com a mesma validação e CSRF dos botões. Serve quando o ID não aparece em Pendentes (fila cheia pelo limite de taxa, ou inundada por IDs falsos) sem precisar de SSH.
- Aprovar: acrescenta `<id> # aprovado AAAA-MM-DD` em `/var/lib/rustdesk-server/allowed.txt` (o hbbs relê o arquivo sozinho, sem restart).
- Bloquear: grava em `blocked.txt` (mesma pasta; é só controle do painel, o hbbs nunca lê esse arquivo — o efeito vem de sair do `allowed.txt`), tira de pendentes e aprovados. Remover: tira só do `allowed.txt`, mantendo as demais linhas.
- Segurança: cookie de sessão HttpOnly/Secure/SameSite=Strict, token CSRF em todo POST, 5 senhas erradas por IP = bloqueio de 10 min. Escuta só em `127.0.0.1:3300`; o Caddy faz o HTTPS.

## Senha

Fica somente em `/etc/everydesk-admin.env` na VPS (`ADMIN_PASSWORD=...`, chmod 600). Nunca no repositório.

Trocar a senha:

```
ssh vps-fachini
echo "ADMIN_PASSWORD=$(openssl rand -base64 18)" > /etc/everydesk-admin.env && chmod 600 /etc/everydesk-admin.env
systemctl restart everydesk-admin   # encerra as sessões abertas
cat /etc/everydesk-admin.env        # para ler a nova senha
```

## Operação

- Status/logs: `systemctl status everydesk-admin`, `journalctl -u everydesk-admin`.
- Reiniciar: `systemctl restart everydesk-admin`.
- Variáveis (na unit): `ALLOWLIST_FILE`, `PENDING_FILE`, `BIND`.
- Build: `cd admin && cargo zigbuild --release --target x86_64-unknown-linux-musl`; copiar `target/x86_64-unknown-linux-musl/release/everydesk-admin` para `/usr/local/bin/`.
- hbbs precisa de `Environment=PENDING_FILE=/var/lib/rustdesk-server/pending.txt` no `override.conf` (aplicado no próximo deploy do hbbs).

## Endurecimento

- hbbs só grava IDs no pending se casarem com o padrão do painel (minúsculas/dígitos, 6-16), no máx. 5 IDs novos por IP e 60 no total a cada 10 min; a gravação roda fora do loop de rede. Arquivos são reescritos por temp+rename mantendo dono/permissão.
- Sessão do painel expira em 24 h. Linhas do `allowed.txt` com ID fora do padrão aparecem sem botão Remover (edite o arquivo).
- A unit usa `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/rustdesk-server`, `ProtectHome`, `PrivateTmp`. Segue como `User=root` porque o hbbs roda como root e é dono dos arquivos; usuário dedicado compartilhado fica como endurecimento futuro.
