'use strict';

/**
 * evo-passkey-injector — sidecar do Passkey Linker (Abordagem B).
 *
 * Um unico sidecar que injeta uma sessao WhatsApp Web existente em DOIS backends
 * (imagens black-box, sem endpoint de import), gravando direto no Postgres de cada um:
 *
 *   • Evolution API (Baileys)     -> tabela "Session".creds (JSON duplo-encodado)
 *       POST /import-creds        body { instanceName, credsEncoded }
 *   • Evolution Go (whatsmeow)    -> whatsmeow_device (evogo_auth) + instances.jid (evogo_users)
 *       POST /evogo/import-creds  body { instanceId, creds }
 *
 * Cada backend e OPCIONAL e ligado por suas envs (ver .env.example). Rode o sidecar na
 * MESMA rede do(s) Postgres — o banco NUNCA precisa ser exposto; exponha so este HTTP
 * (autenticado por segredo compartilhado, o mesmo do painel do zpro).
 *
 * Contrato comum: header x-injector-secret: <INJECTOR_SECRET>; GET /health.
 *
 * PEGADINHA Evolution API (validada no fonte do Evolution v2.3.7): "Session".creds e
 * DUPLO-encodada: coluna = JSON.stringify(JSON.stringify(creds, BufferJSON.replacer)).
 * O zpro manda o encode interno (credsEncoded); aqui embrulhamos DE NOVO.
 *
 * PEGADINHAS Evolution Go (validadas vs sqlstore whatsmeow + banco vivo): device guarda
 * SO a chave PRIVADA (32B; a publica e derivada no load); pub Baileys pode vir 33B com
 * prefixo libsignal 0x05 (remover); adv_key vazio -> 32 zeros (coluna NOT NULL); account
 * (ADV) obrigatorio (colunas adv_* NOT NULL com CHECK de tamanho); jid = FULL AD JID
 * "user:device@s.whatsapp.net" (identico ao instances.jid gravado pelo pareamento por QR).
 */

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = parseInt(process.env.PORT || '8080', 10);
const INJECTOR_SECRET = process.env.INJECTOR_SECRET || '';

// Evolution API (Baileys): 1 banco.
const EVO_DATABASE_URI = process.env.EVO_DATABASE_URI || '';
// Evolution Go (whatsmeow): 2 bancos (store + instancias) no mesmo servidor.
const EVOGO_AUTH_DATABASE_URI = process.env.EVOGO_AUTH_DATABASE_URI || '';
const EVOGO_USERS_DATABASE_URI = process.env.EVOGO_USERS_DATABASE_URI || '';

if (!INJECTOR_SECRET) {
  console.error('[injector] FATAL: INJECTOR_SECRET nao definido');
  process.exit(1);
}

const evoEnabled = !!EVO_DATABASE_URI;
const evogoEnabled = !!(EVOGO_AUTH_DATABASE_URI && EVOGO_USERS_DATABASE_URI);

if (!evoEnabled && !evogoEnabled) {
  console.error(
    '[injector] FATAL: configure EVO_DATABASE_URI (Evolution API) e/ou ' +
      'EVOGO_AUTH_DATABASE_URI + EVOGO_USERS_DATABASE_URI (Evolution Go)'
  );
  process.exit(1);
}

const poolOpts = { max: 4, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000 };
const evoPool = evoEnabled ? new Pool({ connectionString: EVO_DATABASE_URI, ...poolOpts }) : null;
const authPool = evogoEnabled ? new Pool({ connectionString: EVOGO_AUTH_DATABASE_URI, ...poolOpts }) : null;
const usersPool = evogoEnabled ? new Pool({ connectionString: EVOGO_USERS_DATABASE_URI, ...poolOpts }) : null;

console.log(
  `[injector] backends: evolution-api=${evoEnabled ? 'on' : 'off'} evolution-go=${evogoEnabled ? 'on' : 'off'}`
);

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

// ── Evolution Go: decode Contrato A -> colunas whatsmeow_device ──────────────

class CredsError extends Error {
  constructor(code, detail) {
    super(detail || code);
    this.code = code;
  }
}

function b64(s) {
  return Buffer.from(String(s || ''), 'base64');
}

// base64 -> 32 bytes. Aceita 32 crus OU 33 com prefixo libsignal 0x05 (DjbECPublicKey).
function key32(s, name) {
  const b = b64(s);
  if (b.length === 32) return b;
  if (b.length === 33 && b[0] === 0x05) return b.subarray(1);
  throw new CredsError('CREDS_INVALID', `${name}: esperado 32/33 bytes, veio ${b.length}`);
}

function sig64(s, name) {
  const b = b64(s);
  if (b.length !== 64) {
    throw new CredsError('CREDS_INVALID', `${name}: esperado 64 bytes, veio ${b.length}`);
  }
  return b;
}

// Normaliza JID pro formato whatsmeow JID.String(): "user:device@server" (device 0 omitido,
// sufixo de agent ".N" do Baileys removido).
function normalizeJid(id, name) {
  const v = String(id || '').trim();
  const at = v.indexOf('@');
  if (at <= 0) {
    throw new CredsError('CREDS_INVALID', `${name}: JID invalido "${v}"`);
  }
  let local = v.slice(0, at);
  const server = v.slice(at + 1);
  local = local.replace(/\.\d+(?=:|$)/, '');
  if (local.endsWith(':0')) local = local.slice(0, -2);
  if (!local) {
    throw new CredsError('CREDS_INVALID', `${name}: JID invalido "${v}"`);
  }
  return `${local}@${server}`;
}

function buildDeviceRow(creds) {
  if (!creds || typeof creds !== 'object') {
    throw new CredsError('CREDS_INVALID', 'creds ausente ou nao-objeto');
  }
  const { noiseKey, signedIdentityKey, signedPreKey, account, me } = creds;
  if (!noiseKey || !noiseKey.private || !signedIdentityKey || !signedIdentityKey.private) {
    throw new CredsError('CREDS_INVALID', 'noiseKey.private/signedIdentityKey.private obrigatorios');
  }
  if (!signedPreKey || !signedPreKey.keyPair || !signedPreKey.keyPair.private || !signedPreKey.signature) {
    throw new CredsError('CREDS_INVALID', 'signedPreKey incompleto');
  }
  if (typeof creds.registrationId !== 'number') {
    throw new CredsError('CREDS_INVALID', 'registrationId ausente');
  }
  if (!me || !me.id) {
    throw new CredsError('CREDS_INVALID', 'me.id ausente');
  }
  if (!account || !account.details || !account.accountSignature || !account.accountSignatureKey || !account.deviceSignature) {
    // Colunas adv_* sao NOT NULL com CHECK de tamanho — sem o ADV nao ha device valido.
    throw new CredsError('CREDS_MISSING_ACCOUNT', 'creds.account (ADV) obrigatorio p/ Evolution Go');
  }

  // advSecretKey vazio -> 32 bytes zero (ver PEGADINHAS no topo).
  let advKey = b64(creds.advSecretKey);
  if (advKey.length === 0) advKey = Buffer.alloc(32);

  return {
    jid: normalizeJid(me.id, 'me.id'),
    lid: me.lid ? normalizeJid(me.lid, 'me.lid') : null,
    registrationId: creds.registrationId >>> 0,
    noiseKey: key32(noiseKey.private, 'noiseKey.private'),
    identityKey: key32(signedIdentityKey.private, 'signedIdentityKey.private'),
    signedPreKey: key32(signedPreKey.keyPair.private, 'signedPreKey.keyPair.private'),
    signedPreKeyId: Number(signedPreKey.keyId) || 0,
    signedPreKeySig: sig64(signedPreKey.signature, 'signedPreKey.signature'),
    advKey,
    advDetails: b64(account.details),
    advAccountSig: sig64(account.accountSignature, 'account.accountSignature'),
    advAccountSigKey: key32(account.accountSignatureKey, 'account.accountSignatureKey'),
    advDeviceSig: sig64(account.deviceSignature, 'account.deviceSignature'),
    platform: String(creds.platform || ''),
    pushName: String((me && me.name) || '')
  };
}

const app = express();
app.use(express.json({ limit: '15mb' }));

app.get('/health', async (_req, res) => {
  try {
    if (evoPool) await evoPool.query('SELECT 1');
    if (authPool) await authPool.query('SELECT 1');
    if (usersPool) await usersPool.query('SELECT 1');
    return res.json({ ok: true, evolutionApi: evoEnabled, evolutionGo: evogoEnabled });
  } catch (_e) {
    return res.status(500).json({ ok: false, error: 'DB_UNREACHABLE' });
  }
});

// ── Evolution API (Baileys) ──────────────────────────────────────────────────
app.post('/import-creds', requireSecret, async (req, res) => {
  if (!evoPool) {
    return res.status(503).json({ error: 'EVOLUTION_API_NOT_CONFIGURED' });
  }

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

  const client = await evoPool.connect();
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
      `[injector] evo import instance=${instanceName} sessionId=${sessionId} ` +
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
    console.error(`[injector] evo import falhou instance=${instanceName}: ${(e && e.message) || e}`);
    return res.status(500).json({ error: 'IMPORT_FAILED' });
  } finally {
    client.release();
  }
});

// ── Evolution Go (whatsmeow) ─────────────────────────────────────────────────
app.post('/evogo/import-creds', requireSecret, async (req, res) => {
  if (!authPool || !usersPool) {
    return res.status(503).json({ error: 'EVOLUTION_GO_NOT_CONFIGURED' });
  }

  const body = req.body || {};
  const instanceId = body.instanceId;

  if (!instanceId || typeof instanceId !== 'string') {
    return res.status(400).json({ error: 'INSTANCE_ID_REQUIRED' });
  }

  let row;
  try {
    row = buildDeviceRow(body.creds);
  } catch (e) {
    if (e instanceof CredsError) {
      console.error(`[injector] evogo creds invalidas instance=${instanceId}: ${e.message}`);
      return res.status(400).json({ error: e.code, detail: e.message });
    }
    throw e;
  }

  try {
    // 1) Instancia precisa existir no evogo_users (criada antes pelo zpro via /instance/create).
    const inst = await usersPool.query('SELECT id, jid FROM instances WHERE id = $1', [instanceId]);
    if (!inst.rows.length) {
      return res.status(404).json({ error: 'INSTANCE_NOT_FOUND' });
    }

    // Audit sem vazar segredo: jid novo + hash curto da identity key.
    const ikHash = crypto.createHash('sha256').update(row.identityKey).digest('hex').slice(0, 12);
    console.log(
      `[injector] evogo import instance=${instanceId} jid=${row.jid} lid=${row.lid || '-'} ` +
        `oldJid=${inst.rows[0].jid || '-'} ikSha=${ikHash}`
    );

    // 2) Device whatsmeow no evogo_auth (upsert por jid; children preservados no conflito).
    await authPool.query(
      `INSERT INTO whatsmeow_device (
         jid, lid, registration_id, noise_key, identity_key,
         signed_pre_key, signed_pre_key_id, signed_pre_key_sig,
         adv_key, adv_details, adv_account_sig, adv_account_sig_key, adv_device_sig,
         platform, business_name, push_name
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'',$15)
       ON CONFLICT (jid) DO UPDATE SET
         lid = EXCLUDED.lid,
         registration_id = EXCLUDED.registration_id,
         noise_key = EXCLUDED.noise_key,
         identity_key = EXCLUDED.identity_key,
         signed_pre_key = EXCLUDED.signed_pre_key,
         signed_pre_key_id = EXCLUDED.signed_pre_key_id,
         signed_pre_key_sig = EXCLUDED.signed_pre_key_sig,
         adv_key = EXCLUDED.adv_key,
         adv_details = EXCLUDED.adv_details,
         adv_account_sig = EXCLUDED.adv_account_sig,
         adv_account_sig_key = EXCLUDED.adv_account_sig_key,
         adv_device_sig = EXCLUDED.adv_device_sig,
         platform = EXCLUDED.platform,
         push_name = EXCLUDED.push_name`,
      [
        row.jid, row.lid, row.registrationId, row.noiseKey, row.identityKey,
        row.signedPreKey, row.signedPreKeyId, row.signedPreKeySig,
        row.advKey, row.advDetails, row.advAccountSig, row.advAccountSigKey, row.advDeviceSig,
        row.platform, row.pushName
      ]
    );

    // 3) Vincula instancia -> device (mesmo efeito do PairSuccess): no proximo
    //    /instance/connect o Evolution Go carrega o device e conecta sem QR.
    await usersPool.query(
      "UPDATE instances SET jid = $1, connected = true, qrcode = '' WHERE id = $2",
      [row.jid, instanceId]
    );

    return res.json({ success: true, jid: row.jid });
  } catch (e) {
    console.error(`[injector] evogo import falhou instance=${instanceId}: ${(e && e.message) || e}`);
    return res.status(500).json({ error: 'IMPORT_FAILED' });
  }
});

// 404 padrao
app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));

const server = app.listen(PORT, () => {
  console.log(`[injector] ouvindo na porta ${PORT}`);
});

// Encerramento limpo
function shutdown() {
  console.log('[injector] encerrando...');
  server.close(() => {
    const ends = [evoPool, authPool, usersPool].filter(Boolean).map(p => p.end());
    Promise.allSettled(ends).finally(() => process.exit(0));
  });
  // failsafe
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
