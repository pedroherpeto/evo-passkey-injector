'use strict';

/**
 * evo-passkey-injector — sidecar do Passkey Linker (Abordagem B) para o Evolution API.
 *
 * Por que existe: o Evolution roda como imagem oficial (black-box) e NAO tem endpoint HTTP
 * para injetar creds do Baileys. O unico caminho e o Postgres dele (tabela "Session"), que e
 * interno ao host do Evolution e NAO deve ser exposto. Este sidecar sobe na MESMA rede do
 * Evolution (evolution-net), fala com o Postgres por dentro (postgres:5432) e expoe um unico
 * endpoint HTTP autenticado por segredo compartilhado. O zpro POSTa as creds aqui — igual faz
 * com WuzAPI/UAZAPI.
 *
 * Contrato:
 *   POST /import-creds   header x-injector-secret: <INJECTOR_SECRET>
 *        body { instanceName: "<nome da instancia no Evolution>", credsEncoded: "<string>" }
 *        credsEncoded = JSON.stringify(creds, BufferJSON.replacer) — ja 1x-encodado pelo zpro.
 *        -> 200 { success:true, sessionId } | 404 INSTANCE_NOT_FOUND | 401 UNAUTHORIZED
 *   GET  /health -> { ok:true } (pinga o DB)
 *
 * PEGADINHA (validada no fonte do Evolution v2.3.7): a coluna "Session".creds e DUPLO-encodada:
 *   coluna = JSON.stringify(JSON.stringify(creds, BufferJSON.replacer))
 * O zpro manda o encode interno (credsEncoded); aqui embrulhamos DE NOVO (o 2o stringify).
 */

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = parseInt(process.env.PORT || '8080', 10);
const INJECTOR_SECRET = process.env.INJECTOR_SECRET || '';
const EVO_DATABASE_URI = process.env.EVO_DATABASE_URI || '';

if (!INJECTOR_SECRET) {
  console.error('[evo-injector] FATAL: INJECTOR_SECRET nao definido');
  process.exit(1);
}
if (!EVO_DATABASE_URI) {
  console.error('[evo-injector] FATAL: EVO_DATABASE_URI nao definido');
  process.exit(1);
}

const pool = new Pool({
  connectionString: EVO_DATABASE_URI,
  max: 4,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

// Comparacao de segredo em tempo constante (guarda de tamanho vaza so o comprimento).
function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  try {
    return crypto.timingSafeEqual(ba, bb);
  } catch (_e) {
    return false;
  }
}

function requireSecret(req, res, next) {
  const provided = req.get('x-injector-secret') || '';
  if (!timingSafeEqualStr(provided, INJECTOR_SECRET)) {
    return res.status(401).json({ error: 'UNAUTHORIZED' });
  }
  return next();
}

const app = express();
app.use(express.json({ limit: '15mb' }));

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    return res.json({ ok: true });
  } catch (_e) {
    return res.status(500).json({ ok: false, error: 'DB_UNREACHABLE' });
  }
});

app.post('/import-creds', requireSecret, async (req, res) => {
  const body = req.body || {};
  const instanceName = body.instanceName;
  const credsEncoded = body.credsEncoded;

  if (!instanceName || typeof instanceName !== 'string') {
    return res.status(400).json({ error: 'INSTANCE_NAME_REQUIRED' });
  }
  if (!credsEncoded || typeof credsEncoded !== 'string') {
    return res.status(400).json({ error: 'CREDS_REQUIRED' });
  }

  // Sanidade: credsEncoded deve ser um JSON de objeto (formato BufferJSON). Nao usa reviver aqui —
  // so confirma que nao e lixo antes de gravar.
  try {
    const parsed = JSON.parse(credsEncoded);
    if (!parsed || typeof parsed !== 'object') {
      return res.status(400).json({ error: 'CREDS_INVALID' });
    }
  } catch (_e) {
    return res.status(400).json({ error: 'CREDS_INVALID' });
  }

  // Duplo-encode do Evolution: a coluna guarda uma string JSON de uma string JSON.
  const stored = JSON.stringify(credsEncoded);

  const client = await pool.connect();
  try {
    // sessionId da tabela Session = Instance.id (cuid), resolvido pelo NOME da instancia.
    const inst = await client.query('SELECT id FROM "Instance" WHERE name = $1', [instanceName]);
    if (!inst.rows.length) {
      return res.status(404).json({ error: 'INSTANCE_NOT_FOUND' });
    }
    const sessionId = inst.rows[0].id;

    // Audit da linha antiga (sem vazar o conteudo/segredo): tamanho + hash curto.
    const old = await client.query('SELECT creds FROM "Session" WHERE "sessionId" = $1', [sessionId]);
    const oldCreds = old.rows[0] && old.rows[0].creds ? old.rows[0].creds : '';
    const oldLen = oldCreds.length;
    const oldHash = oldLen
      ? crypto.createHash('sha256').update(oldCreds).digest('hex').slice(0, 12)
      : '-';
    console.log(
      `[evo-injector] import instance=${instanceName} sessionId=${sessionId} ` +
        `oldCredsLen=${oldLen} oldCredsSha=${oldHash} newCredsLen=${stored.length}`
    );

    await client.query(
      `INSERT INTO "Session" (id, "sessionId", creds, "createdAt")
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT ("sessionId") DO UPDATE SET creds = EXCLUDED.creds`,
      [crypto.randomUUID(), sessionId, stored]
    );

    return res.json({ success: true, sessionId });
  } catch (e) {
    console.error(`[evo-injector] import falhou instance=${instanceName}: ${(e && e.message) || e}`);
    return res.status(500).json({ error: 'IMPORT_FAILED' });
  } finally {
    client.release();
  }
});

// 404 padrao
app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));

const server = app.listen(PORT, () => {
  console.log(`[evo-injector] ouvindo na porta ${PORT}`);
});

// Encerramento limpo
function shutdown() {
  console.log('[evo-injector] encerrando...');
  server.close(() => {
    pool.end().finally(() => process.exit(0));
  });
  // failsafe
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
