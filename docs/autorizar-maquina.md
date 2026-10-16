# Autorizar uma máquina no EveryDesk

O servidor (`hbbs`) só aceita IDs listados em `/var/lib/rustdesk-server/allowed.txt` (um ID por linha).

## Autorizar um ID

```bash
ssh vps-fachini 'echo <ID> >> /var/lib/rustdesk-server/allowed.txt'
```

O arquivo precisa terminar com uma quebra de linha; variante segura: `ssh vps-fachini "printf '\n<ID>\n' >> /var/lib/rustdesk-server/allowed.txt"`.
O ID é o número de 9 dígitos mostrado na janela do EveryDesk da máquina.
Comentários com `#` são permitidos, por exemplo `<ID> # PC da Maria`, para anotar o dono da máquina.

## Listar IDs autorizados

```bash
ssh vps-fachini 'cat /var/lib/rustdesk-server/allowed.txt'
```

## Remover um ID

```bash
ssh vps-fachini "sed -i '/^<ID>$/d' /var/lib/rustdesk-server/allowed.txt"
```

A lista é relida automaticamente quando o arquivo muda (mtime); não é preciso reiniciar o hbbs.
