# evo-passkey-injector

Sidecar do **Passkey Linker** para o **Evolution API**. Injeta as credenciais do WhatsApp Web
(extraídas sem QR pela extensão) na store do Evolution, permitindo conectar um canal `evo` **sem
escanear QR** — contornando a exigência de passkey.

## Por que existe

O Evolution roda como imagem oficial (black-box) e **não tem endpoint HTTP** para injetar creds do
Baileys. O único caminho é o **Postgres** dele (tabela `Session`), que é interno ao host do Evolution
e **não deve ser exposto** (a senha padrão costuma ser fraca). Este sidecar:

- sobe na **mesma rede** do Evolution (`evolution-net`) e fala com o Postgres por dentro (`postgres:5432`);
- expõe **um único endpoint** HTTP autenticado por segredo compartilhado;
- é o que o zpro chama para importar as creds — igual ao que já é feito com WuzAPI/UAZAPI.

O Evolution **sem** este sidecar continua funcionando por QR normalmente. O sidecar só habilita o
import-por-passkey no Evolution.

## Deploy (1 sidecar por servidor Evolution — não por usuário)

1. **Suba o serviço** junto do seu Evolution: copie o bloco de `docker-compose.example.yml` para o
   `docker-compose.yml` que já tem `api`/`postgres`/`redis`, na rede `evolution-net`. Usa a imagem
   publicada **`zdgzpro/evo-passkey-injector:latest`** (Docker Hub) — sem build no cliente.
2. **Defina o segredo**: `EVO_INJECTOR_SECRET` (gere com `openssl rand -hex 32`).
3. **Ajuste o DSN**: `EVO_DATABASE_URI` apontando para o Postgres interno do Evolution.
4. **No painel do zpro**: `Configurações → Evolution` → preencha **URL do injector** e **Segredo do
   injector** (o mesmo `EVO_INJECTOR_SECRET`).

- **zpro no mesmo host** do Evolution: mantenha o port em `127.0.0.1` (só local); a URL do injector
  no painel fica tipo `http://127.0.0.1:8082`.
- **zpro em host separado**: exponha o port atrás de **HTTPS/reverse-proxy**; a URL do injector fica
  o domínio público do sidecar. O `INJECTOR_SECRET` protege o endpoint (nunca exponha o Postgres).

## Variáveis de ambiente

| Var | Descrição |
|---|---|
| `PORT` | Porta HTTP (default 8080). |
| `INJECTOR_SECRET` | Segredo compartilhado com o zpro (header `x-injector-secret`). Obrigatório. |
| `EVO_DATABASE_URI` | DSN do Postgres do Evolution (nome de serviço interno). Obrigatório. |

## API

```
POST /import-creds
  Header:  x-injector-secret: <INJECTOR_SECRET>
  Body:    { "instanceName": "<nome da instância>", "credsEncoded": "<string BufferJSON>" }
  200:     { "success": true, "sessionId": "<cuid>" }
  400:     INSTANCE_NAME_REQUIRED | CREDS_REQUIRED | CREDS_INVALID
  401:     UNAUTHORIZED (segredo inválido)
  404:     INSTANCE_NOT_FOUND (nome não existe na tabela Instance)
  500:     IMPORT_FAILED

GET /health -> { "ok": true }   (pinga o banco)
```

> `credsEncoded` = `JSON.stringify(creds, BufferJSON.replacer)` (já 1x-encodado pelo zpro). O sidecar
> **embrulha uma segunda vez** (`JSON.stringify(credsEncoded)`) porque a coluna `Session.creds` do
> Evolution é **duplo-encodada** (validado no fonte v2.3.7). Depois de gravar, o zpro chama
> `GET /instance/connect/{nome}` no Evolution para reconectar sem QR.

## Segurança

- O Postgres do Evolution **nunca** é exposto — só o sidecar o alcança, por dentro da rede.
- Segredo comparado em **tempo constante**; requisições sem o header correto recebem 401.
- Os logs **não** vazam o conteúdo das creds (apenas tamanho + hash curto para auditoria).
- **Rollback**: o injector loga o tamanho/hash da linha antiga antes de sobrescrever. Como só se
  injeta em instâncias travadas no QR (creds antigas inúteis), o risco é baixo; para paranoia,
  faça snapshot do `evolution_db` antes.

## Dev local

```bash
npm install
cp .env.example .env   # edite os valores
npm run check          # node --check
npm start
```
