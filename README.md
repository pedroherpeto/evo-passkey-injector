# evo-passkey-injector

Sidecar do **Passkey Linker** (Abordagem B). Injeta uma sessão do WhatsApp Web (extraída sem QR pela
extensão) direto na store de backends que rodam como imagem **black-box** — permitindo conectar o canal
**sem escanear QR**. Um único sidecar serve **dois** backends:

| Backend | Store | Endpoint |
|---|---|---|
| **Evolution API** (Baileys) | Postgres — tabela `Session.creds` (JSON duplo-encodado) | `POST /import-creds` |
| **Evolution Go** (whatsmeow) | Postgres — `whatsmeow_device` (`evogo_auth`) + `instances.jid` (`evogo_users`) | `POST /evogo/import-creds` |

Cada backend é **opcional** e ligado pelas suas variáveis de ambiente. Rode o sidecar na **mesma rede**
do(s) Postgres — o banco **nunca** precisa ser exposto; exponha só este HTTP (autenticado por segredo).

## Por que existe

Evolution API e Evolution Go rodam como imagens black-box e **não têm endpoint HTTP** para importar uma
sessão. O único caminho é o **Postgres** de cada um, que é interno ao host e **não deve ser exposto**.
Este sidecar sobe na rede interna, fala com o(s) banco(s) por dentro, e expõe um único endpoint
autenticado — igual ao que o zpro já faz com WuzAPI/UAZAPI. Sem o sidecar, os canais continuam
funcionando por QR normalmente; o sidecar só habilita o import-por-passkey.

## Deploy (1 sidecar por servidor — não por usuário)

1. **Suba o serviço** junto do seu Evolution/Evolution Go: copie o bloco de `docker-compose.example.yml`
   para o `docker-compose.yml` que já tem os serviços, na mesma rede do Postgres. Usa a imagem publicada
   **`zdgzpro/evo-passkey-injector:latest`** (Docker Hub) — sem build no cliente.
2. **Defina o segredo**: `INJECTOR_SECRET` (gere com `openssl rand -hex 32`).
3. **Ligue o(s) backend(s)** preenchendo as DSNs (ver tabela abaixo). Pelo menos um bloco é obrigatório.
4. **No painel do zpro**: `Configurações → Evolution` e/ou `Configurações → Evolution Go` → preencha
   **URL do injector** e **Segredo do injector** (o mesmo `INJECTOR_SECRET`). Se você usa os dois
   canais com o mesmo sidecar, aponte as duas telas para a **mesma URL/segredo**.

- **zpro no mesmo host**: mantenha o port em `127.0.0.1` (só local); URL do injector tipo `http://127.0.0.1:8082`.
- **zpro em host separado**: exponha atrás de **HTTPS/reverse-proxy**; o `INJECTOR_SECRET` protege o endpoint.

## Variáveis de ambiente

| Var | Descrição |
|---|---|
| `PORT` | Porta HTTP (default 8080). |
| `INJECTOR_SECRET` | Segredo compartilhado com o zpro (header `x-injector-secret`). **Obrigatório.** |
| `EVO_DATABASE_URI` | DSN do Postgres do Evolution API. Liga o endpoint `/import-creds`. Opcional. |
| `EVOGO_AUTH_DATABASE_URI` | DSN do banco `evogo_auth` (store whatsmeow). |
| `EVOGO_USERS_DATABASE_URI` | DSN do banco `evogo_users` (instâncias). Os dois juntos ligam `/evogo/import-creds`. Opcional. |

Pelo menos um backend (Evolution API **ou** Evolution Go) precisa estar configurado, senão o processo aborta.

## API

```
POST /import-creds                 (Evolution API)
  Header:  x-injector-secret: <INJECTOR_SECRET>
  Body:    { "instanceName": "<nome da instância>", "credsEncoded": "<string BufferJSON>" }
  200:     { "success": true, "sessionId": "<cuid>" }
  400:     INSTANCE_NAME_REQUIRED | CREDS_REQUIRED | CREDS_INVALID
  401:     UNAUTHORIZED       404: INSTANCE_NOT_FOUND       503: EVOLUTION_API_NOT_CONFIGURED

POST /evogo/import-creds           (Evolution Go)
  Header:  x-injector-secret: <INJECTOR_SECRET>
  Body:    { "instanceId": "<uuid da instância>", "creds": { ...formato Baileys/base64 } }
  200:     { "success": true, "jid": "5511...:23@s.whatsapp.net" }
  400:     INSTANCE_ID_REQUIRED | CREDS_INVALID | CREDS_MISSING_ACCOUNT
  401:     UNAUTHORIZED       404: INSTANCE_NOT_FOUND       503: EVOLUTION_GO_NOT_CONFIGURED

GET /health -> { "ok": true, "evolutionApi": <bool>, "evolutionGo": <bool> }
```

> **Evolution API**: `credsEncoded` = `JSON.stringify(creds, BufferJSON.replacer)` (já 1x-encodado pelo
> zpro). O sidecar **embrulha uma segunda vez** porque a coluna `Session.creds` é **duplo-encodada**
> (validado no fonte v2.3.7). Depois de gravar, o zpro chama `GET /instance/connect/{nome}`.
>
> **Evolution Go**: o zpro manda as creds **cruas** (Contrato A); a conversão para o device whatsmeow
> acontece no sidecar (ref `import_web_creds.go` da WuzAPI). Depois de gravar `whatsmeow_device` +
> `instances.jid`, o zpro dispara `/instance/connect` e o Evolution Go conecta sem QR (Store.ID != nil).

## Notas técnicas Evolution Go (não óbvias)

- `whatsmeow_device` guarda **só a chave privada** (32 bytes) de noiseKey/identityKey/signedPreKey — a
  pública é derivada no load. Nunca gravar a pública nessas colunas.
- Chaves públicas do Baileys podem vir com prefixo libsignal `0x05` (33 bytes) — é removido.
- `advSecretKey` costuma vir vazio pós-pareamento → substituído por 32 bytes zero (coluna NOT NULL).
- `creds.account` (ADV) é obrigatório: colunas `adv_*` são NOT NULL com CHECK de tamanho.
- O `jid` gravado é o FULL AD JID (`user:device@s.whatsapp.net`), idêntico ao que o QR grava em `instances.jid`.

## Segurança

- O(s) Postgres **nunca** é exposto — só o sidecar o alcança, por dentro da rede.
- Segredo comparado em **tempo constante**; requisições sem o header correto recebem 401.
- Os logs **não** vazam o conteúdo das creds (apenas tamanho/hash curto para auditoria).

## Dev local

```bash
npm install
cp .env.example .env   # edite os valores
npm run check          # node --check
npm start
```
