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

## UI web (`GET /`) — uso manual sem o zpro

Além do contrato de máquina (usado pelo zpro), o sidecar serve uma **página web** em `/` para uso manual
por outros sistemas: cole o JSON de creds da extensão (**"Copiar creds"**), escolha a sessão já criada no
Evolution/Evolution Go e clique **Conectar**. A UI fala **só com este sidecar** (mesma origem = zero CORS);
o segredo e as apikeys ficam no servidor. Funciona para **Evolution API e Evolution Go ao mesmo tempo**
(o seletor de canal aparece conforme os backends ligados). Abra `http://<host-do-injector>:<porta>/`.

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
| `EVO_API_URL` | Base HTTP da API do Evolution (ex.: `http://evolution_api:8080`). Liga o **connect ao vivo** do Evolution API. Opcional. |
| `EVO_API_KEY` | `AUTHENTICATION_API_KEY` (global) do Evolution API. Usado no connect. Opcional. |
| `EVOGO_API_URL` | Base HTTP da API do Evolution Go (ex.: `http://evogo:8082`). Liga o **connect ao vivo** do Evolution Go (usa o token por-instância do banco). Opcional. |
| `EVOGO_API_KEY` | `GLOBAL_API_KEY` do Evolution Go. Só necessário para **criar sessão** pela UI. Opcional. |

Pelo menos um backend (Evolution API **ou** Evolution Go) precisa estar configurado, senão o processo aborta.
As quatro últimas são **opcionais**: sem elas o import ainda grava as creds e a sessão sobe no próximo
connect/restart do backend; com elas o botão **Conectar** sobe a sessão na hora.

> **Redes docker:** o injector precisa alcançar o(s) **Postgres** *e* a(s) **API(s)**. Se Evolution e
> Evolution Go rodam em redes diferentes, **conecte o injector às duas** (`docker network connect`).

## API

Todos os endpoints de dados exigem o header `x-injector-secret: <INJECTOR_SECRET>`.

```
GET  /                             UI web (public/index.html) — sem segredo

POST /import-creds                 (Evolution API) — import
  Body:    { "instanceName": "<nome>", "credsEncoded": "<string BufferJSON>" }
       ou: { "instanceName": "<nome>", "creds": { ...dump cru da extensao } }
  200:     { "success": true, "sessionId": "<cuid>" }
  400:     INSTANCE_NAME_REQUIRED | CREDS_REQUIRED | CREDS_INVALID
  401:     UNAUTHORIZED       404: INSTANCE_NOT_FOUND       503: EVOLUTION_API_NOT_CONFIGURED

POST /evogo/import-creds           (Evolution Go) — import
  Body:    { "instanceId": "<uuid>", "creds": { ...dump cru da extensao } }
  200:     { "success": true, "jid": "5511...:23@s.whatsapp.net" }
  400:     INSTANCE_ID_REQUIRED | CREDS_INVALID | CREDS_MISSING_ACCOUNT
  401:     UNAUTHORIZED       404: INSTANCE_NOT_FOUND       503: EVOLUTION_GO_NOT_CONFIGURED

GET  /evo/instances                lista { instances:[{id,name}] }               (Evolution API)
GET  /evogo/instances              lista { instances:[{id,name,jid,connected}] }  (Evolution Go)

POST /evogo/create                 cria sessao { name } -> { id, token }  (exige EVOGO_API_URL+KEY)

POST /evo/link                     import + connect ao vivo (Evolution API)
  Body:    { "instanceName": "<nome>", "creds": { ... } }   (ou credsEncoded)
  200:     { success, imported, connected, ... }

POST /evogo/link                   import + connect ao vivo (Evolution Go)
  Body:    { "instanceId": "<uuid>", "creds": { ... }, "webhookUrl": "<opcional>" }
  200:     { success, imported, connected, jid, status, ... }

GET  /health -> { ok, evolutionApi, evolutionGo, connect:{ evolutionApi, evolutionGo, evolutionGoCreate } }
```

> **Dump cru vs `credsEncoded`**: a UI e outros sistemas mandam o **dump cru** da extensão (`creds`) — o
> sidecar faz a conversão Baileys + encode (`initAuthCreds` + `BufferJSON`, self-contained). O zpro manda
> `credsEncoded` já 1x-encodado (compat retro). O dump pode vir puro **ou** como o export completo da
> extensão `{ creds:{...}, warnings, ... }` (o sidecar desce um nível sozinho).

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
