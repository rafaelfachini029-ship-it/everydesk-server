# Autorizar uma máquina no EveryDesk

O servidor (`hbbs`) só aceita IDs listados em `/var/lib/rustdesk-server/allowed.txt` (um ID por linha).

## Autorizar um ID

```bash
ssh vps-fachini 'echo <ID> >> /var/lib/rustdesk-server/allowed.txt'
```

## Listar IDs autorizados

```bash
ssh vps-fachini 'cat /var/lib/rustdesk-server/allowed.txt'
```

## Remover um ID

```bash
ssh vps-fachini "sed -i '/^<ID>$/d' /var/lib/rustdesk-server/allowed.txt"
```

Se a lista não recarregar sozinha, reinicie apenas o hbbs:
`ssh vps-fachini 'systemctl restart rustdesk-hbbs'`
