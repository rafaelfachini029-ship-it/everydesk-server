# Painel de aprovação (everydesk-admin)

Painel web para aprovar, bloquear e remover máquinas da allow-list do hbbs.

- URL: https://everydesk.vpsfachini.online (login por senha única).
- Pendentes: quando o hbbs nega um `RegisterPk` por falta na allow-list, ele anexa `<id> <unix_ts>` em `PENDING_FILE` (`/var/lib/rustdesk-server/pending.txt`, sem duplicatas, máx. 500 linhas).
- Aprovar: acrescenta `<id> # aprovado AAAA-MM-DD` em `/var/lib/rustdesk-server/allowed.txt` (o hbbs relê o arquivo sozinho, sem restart).
- Bloquear: grava em `blocked.txt` (mesma pasta), tira de pendentes e aprovados. Remover: tira só do `allowed.txt`, mantendo as demais linhas.
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
