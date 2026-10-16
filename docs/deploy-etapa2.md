# Deploy etapa 2 (hbbs + hbbr)

Binarios em /usr/bin (estaticos musl). Backups: `*.1.1.16-stock` (original), `*.etapa1` (etapa 1).

## Variaveis de ambiente (drop-ins systemd, chmod 600)
- `/etc/systemd/system/rustdesk-hbbs.service.d/override.conf`: `ALLOWLIST_FILE=/var/lib/rustdesk-server/allowed.txt`, `PENDING_FILE=/var/lib/rustdesk-server/pending.txt`, `RELAY_SECRET`
- `/etc/systemd/system/rustdesk-hbbr.service.d/override.conf`: `KEY=_`, `RELAY_SECRET` (identico ao do hbbs)

`RELAY_SECRET` (openssl rand -base64 32) vive apenas nesses dois arquivos na VPS; nunca em repo/logs. Se trocar, trocar nos dois e reiniciar ambos.

## Rollback para etapa 1
```
systemctl stop rustdesk-hbbs rustdesk-hbbr
install -m755 /usr/bin/hbbs.etapa1 /usr/bin/hbbs
install -m755 /usr/bin/hbbr.etapa1 /usr/bin/hbbr
systemctl start rustdesk-hbbs rustdesk-hbbr
```
(Variaveis extras sao ignoradas pelos binarios etapa 1.) Nao tocar em ponte-djen nem reiniciar caddy; conferir `curl -s https://djen.fachiniecornelioadvocacia.com.br/saude` = ok.
