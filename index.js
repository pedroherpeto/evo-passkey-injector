'use strict';

/**
 * evo-passkey-injector — sidecar do Passkey Linker (Abordagem B).
 *
 * Injeta uma sessao WhatsApp Web existente (extraida sem QR pela extensao) em DOIS
 * backends que rodam como imagem black-box (sem endpoint de import), gravando direto
 * no Postgres de cada um, e — opcionalmente — dispara o /instance/connect pra conectar
 * ao vivo (sem QR):
 *
 *   • Evolution API (Baileys)     -> tabela "Session".creds (JSON duplo-encodado)
 *       POST /import-creds        body { instanceName, credsEncoded }  (ou { instanceName, creds })
 *   • Evolution Go (whatsmeow)    -> whatsmeow_device (evogo_auth) + instances.jid (evogo_users)
 *       POST /evogo/import-creds  body { instanceId, creds }
 *
 * Cada backend e OPCIONAL e ligado por suas envs (ver .env.example). Rode o sidecar na
 * MESMA rede do(s) Postgres — o banco NUNCA precisa ser exposto; exponha so este HTTP
 * (autenticado por segredo compartilhado, o mesmo do painel do zpro).
 *
 * ── UI embutida (GET /) ──────────────────────────────────────────────────────
 * Alem do contrato de maquina (usado pelo zpro), o sidecar serve uma UI web simples
 * em `/` (public/index.html) para uso MANUAL por outros sistemas: cole o JSON de creds
 * da extensao ("Copiar creds"), escolha a sessao ja criada no Evolution/Evolution Go e
 * clique Conectar. A UI fala SO com este sidecar (mesma origem = zero CORS); o segredo e
 * as apikeys ficam no servidor. Endpoints de dados exigem `x-injector-secret`.
 *
 * ── Conectar ao vivo (opcional) ──────────────────────────────────────────────
 * Import so grava no banco. Para subir a sessao na hora, o sidecar chama a API HTTP do
 * backend — ligue com EVO_API_URL/EVO_API_KEY (Evolution API) e/ou EVOGO_API_URL
 * (Evolution Go; connect usa o token POR-INSTANCIA lido da tabela instances; EVOGO_API_KEY
 * global habilita "criar sessao"). Sem esses envs, o import ainda funciona e a sessao sobe
 * no proximo restart/connect do backend.
 *
 * PEGADINHA Evolution API (validada no fonte do Evolution v2.3.7): "Session".creds e
 * DUPLO-encodada: coluna = JSON.stringify(JSON.stringify(creds, BufferJSON.replacer)).
 * Quando o cliente manda `creds` cruas (Contrato A da extensao), a conversao pro objeto
 * Baileys + o encode interno acontecem aqui (ver buildEvoCredsEncoded); depois embrulhamos
 * DE NOVO. Quando manda `credsEncoded` (o zpro faz o encode interno), so embrulhamos 1x.
 *
 * PEGADINHAS Evolution Go (validadas vs sqlstore whatsmeow + banco vivo): device guarda
 * SO a chave PRIVADA (32B; a publica e derivada no load); pub Baileys pode vir 33B com
 * prefixo libsignal 0x05 (remover); adv_key vazio -> 32 zeros (coluna NOT NULL); account
 * (ADV) obrigatorio (colunas adv_* NOT NULL com CHECK de tamanho); jid = FULL AD JID
 * "user:device@s.whatsapp.net" (identico ao instances.jid gravado pelo pareamento por QR).
 */

const path = require('path');
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

// ── Conectar ao vivo (opcional): URL + apikey da API HTTP de cada backend ─────
// Evolution API: connect = GET {EVO_API_URL}/instance/connect/{name} (apikey GLOBAL).
const EVO_API_URL = (process.env.EVO_API_URL || '').replace(/\/+$/, '');
const EVO_API_KEY = process.env.EVO_API_KEY || '';
// Evolution Go: connect = POST {EVOGO_API_URL}/instance/connect (apikey = token POR-INSTANCIA,
// lido da tabela instances). EVOGO_API_KEY (global) so e necessario p/ criar sessao.
const EVOGO_API_URL = (process.env.EVOGO_API_URL || '').replace(/\/+$/, '');
const EVOGO_API_KEY = process.env.EVOGO_API_KEY || '';

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

// Capacidade de conectar ao vivo (import sempre funciona; connect e o extra).
const evoConnectEnabled = evoEnabled && !!EVO_API_URL && !!EVO_API_KEY;
const evogoConnectEnabled = evogoEnabled && !!EVOGO_API_URL;
const evoCreateEnabled = evoEnabled && !!EVO_API_URL && !!EVO_API_KEY;
const evogoCreateEnabled = evogoEnabled && !!EVOGO_API_URL && !!EVOGO_API_KEY;

const poolOpts = { max: 4, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000 };
const evoPool = evoEnabled ? new Pool({ connectionString: EVO_DATABASE_URI, ...poolOpts }) : null;
const authPool = evogoEnabled ? new Pool({ connectionString: EVOGO_AUTH_DATABASE_URI, ...poolOpts }) : null;
const usersPool = evogoEnabled ? new Pool({ connectionString: EVOGO_USERS_DATABASE_URI, ...poolOpts }) : null;

console.log(
  `[injector] backends: evolution-api=${evoEnabled ? 'on' : 'off'} evolution-go=${evogoEnabled ? 'on' : 'off'} ` +
    `| connect: evo=${evoConnectEnabled ? 'on' : 'off'} evogo=${evogoConnectEnabled ? 'on' : 'off'} ` +
    `create: evo=${evoCreateEnabled ? 'on' : 'off'} evogo=${evogoCreateEnabled ? 'on' : 'off'}`
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

// GET com timeout via fetch nativo (Node >= 18). Devolve { ok, status, data }.
async function httpJson(method, url, { apikey, body, timeoutMs = 30000 } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(apikey ? { apikey } : {})
      },
      body: body != null ? JSON.stringify(body) : undefined,
      signal: ctrl.signal
    });
    let data = null;
    const text = await res.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (_e) {
        data = text;
      }
    }
    return { ok: res.ok, status: res.status, data };
  } finally {
    clearTimeout(t);
  }
}

// ── Evolution API (Baileys): creds cruas (Contrato A) -> credsEncoded ─────────
// Replica EXATA do fluxo nativo do zpro (BuildBaileysCredsFromWebDumpZPRO +
// initAuthCreds do baileys-v7/infiniteapi), self-contained: sem depender do Baileys.
// So os campos do skeleton que SOBREVIVEM ao overlay do dump importam
// (pairingEphemeralKeyPair + escalares); noiseKey/signedIdentityKey/signedPreKey/
// registrationId/advSecretKey/registered vem do dump. pairingEphemeralKeyPair nao e
// lido no LOGIN (so no pareamento) — gerado com x25519 nativo so p/ ter shape valido.

// Curve.generateKeyPair() equivalente: par x25519 cru de 32 bytes { private, public }.
function genCurveKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const priv = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
  return { private: priv, public: pub };
}

// initAuthCreds() (infiniteapi/baileys v7) — campos sobrepostos ficam como placeholder.
function initAuthCredsSkeleton() {
  return {
    noiseKey: genCurveKeyPair(),
    pairingEphemeralKeyPair: genCurveKeyPair(),
    signedIdentityKey: genCurveKeyPair(),
    signedPreKey: undefined, // sempre sobreposto pelo dump (campo obrigatorio)
    registrationId: 0,
    advSecretKey: crypto.randomBytes(32).toString('base64'),
    processedHistoryMessages: [],
    nextPreKeyId: 1,
    firstUnuploadedPreKeyId: 1,
    accountSyncCounter: 0,
    accountSettings: { unarchiveChats: false },
    registered: false,
    pairingCode: undefined,
    lastPropHash: undefined,
    routingInfo: undefined,
    additionalData: undefined
  };
}

function dumpB64(v) {
  return v == null ? undefined : Buffer.from(v, 'base64');
}
function dumpKeyPair(o) {
  return o ? { private: dumpB64(o.private), public: dumpB64(o.public) } : undefined;
}

// Contrato A (base64 em strings) -> AuthenticationCreds do Baileys.
// Mesma ordem/logica de BuildBaileysCredsFromWebDumpZPRO (fonte de verdade do zpro).
function buildBaileysCredsFromWebDump(dump) {
  const creds = initAuthCredsSkeleton();
  if (dump.noiseKey) creds.noiseKey = dumpKeyPair(dump.noiseKey);
  if (dump.signedIdentityKey) creds.signedIdentityKey = dumpKeyPair(dump.signedIdentityKey);
  if (dump.signedPreKey) {
    creds.signedPreKey = {
      keyId: dump.signedPreKey.keyId,
      keyPair: dumpKeyPair(dump.signedPreKey.keyPair),
      signature: dumpB64(dump.signedPreKey.signature)
    };
  }
  if (dump.registrationId != null) creds.registrationId = dump.registrationId;
  if (dump.advSecretKey) creds.advSecretKey = dump.advSecretKey;
  if (dump.me) {
    creds.me = {
      id: dump.me.id,
      lid: dump.me.lid || undefined,
      name: dump.me.name || undefined
    };
  }
  if (dump.account) {
    creds.account = {
      details: dumpB64(dump.account.details),
      accountSignatureKey: dumpB64(dump.account.accountSignatureKey),
      accountSignature: dumpB64(dump.account.accountSignature),
      deviceSignature: dumpB64(dump.account.deviceSignature)
    };
  }
  if (dump.nextPreKeyId != null) creds.nextPreKeyId = dump.nextPreKeyId;
  if (dump.firstUnuploadedPreKeyId != null) creds.firstUnuploadedPreKeyId = dump.firstUnuploadedPreKeyId;
  creds.platform = dump.platform || 'web';
  creds.registered = true; // device existente -> login, nao pareamento
  return creds;
}

// BufferJSON.replacer do Baileys (EXATO). JSON.stringify aplica Buffer.toJSON antes do
// replacer -> o replacer ve { type:'Buffer', data:[...bytes] } e re-encoda como base64.
function bufferJsonReplacer(_key, value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array || (value && value.type === 'Buffer')) {
    return { type: 'Buffer', data: Buffer.from(value.data || value).toString('base64') };
  }
  return value;
}

// Campos minimos p/ o Evolution aceitar as creds como device existente (mesmo gate da extensao).
function evoDumpMissing(dump) {
  const missing = [];
  if (!dump || typeof dump !== 'object') return ['creds'];
  if (!dump.noiseKey || !dump.noiseKey.private) missing.push('noiseKey');
  if (!dump.signedIdentityKey || !dump.signedIdentityKey.private) missing.push('identityKey');
  if (!dump.signedPreKey || !dump.signedPreKey.keyPair || !dump.signedPreKey.keyPair.private || !dump.signedPreKey.signature) {
    missing.push('signedPreKey');
  }
  if (dump.registrationId == null) missing.push('registrationId');
  if (!dump.me || !dump.me.id) missing.push('me.id');
  if (!dump.account || !dump.account.details || !dump.account.accountSignature || !dump.account.deviceSignature) {
    missing.push('account');
  }
  return missing;
}

// Dump cru (Contrato A) -> string credsEncoded (encode interno BufferJSON, 1x).
function buildEvoCredsEncoded(dump) {
  const credsObj = buildBaileysCredsFromWebDump(dump);
  return JSON.stringify(credsObj, bufferJsonReplacer);
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

// ── Logica de gravacao (reusada por /import-creds, /evogo/import-creds e /link) ──

// Evolution API: grava credsEncoded (string ja 1x-encodada) na tabela Session (duplo-encode).
async function writeEvoSession(instanceName, credsEncoded) {
  const stored = JSON.stringify(credsEncoded); // duplo-encode do Evolution
  const client = await evoPool.connect();
  try {
    const inst = await client.query('SELECT id FROM "Instance" WHERE name = $1', [instanceName]);
    if (!inst.rows.length) {
      const e = new Error('INSTANCE_NOT_FOUND');
      e.code = 'INSTANCE_NOT_FOUND';
      throw e;
    }
    const sessionId = inst.rows[0].id;

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

    return sessionId;
  } finally {
    client.release();
  }
}

// Evolution Go: grava device whatsmeow + vincula instances.jid. Retorna o jid gravado.
async function writeEvoGoDevice(instanceId, row) {
  const inst = await usersPool.query('SELECT id, jid FROM instances WHERE id = $1', [instanceId]);
  if (!inst.rows.length) {
    const e = new Error('INSTANCE_NOT_FOUND');
    e.code = 'INSTANCE_NOT_FOUND';
    throw e;
  }

  const ikHash = crypto.createHash('sha256').update(row.identityKey).digest('hex').slice(0, 12);
  console.log(
    `[injector] evogo import instance=${instanceId} jid=${row.jid} lid=${row.lid || '-'} ` +
      `oldJid=${inst.rows[0].jid || '-'} ikSha=${ikHash}`
  );

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

  await usersPool.query(
    "UPDATE instances SET jid = $1, connected = true, qrcode = '' WHERE id = $2",
    [row.jid, instanceId]
  );

  return row.jid;
}

// Extrai o dump de creds do body. Aceita { instanceName/instanceId, creds: <dump> },
// e desce mais um nivel se `creds` for o export COMPLETO da extensao
// ({ creds:{...}, warnings, missing }) em vez do objeto de creds puro.
function unwrapDump(body) {
  const b = body || {};
  let d = b.creds != null ? b.creds : b;
  if (
    d && typeof d === 'object' &&
    d.creds && typeof d.creds === 'object' &&
    (d.creds.noiseKey || d.creds.me || d.creds.account)
  ) {
    d = d.creds;
  }
  return d;
}

const app = express();
app.use(express.json({ limit: '15mb' }));
// UI web (mesma origem): GET / -> public/index.html. So GET/HEAD; nao intercepta os POST.
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', async (_req, res) => {
  try {
    if (evoPool) await evoPool.query('SELECT 1');
    if (authPool) await authPool.query('SELECT 1');
    if (usersPool) await usersPool.query('SELECT 1');
    return res.json({
      ok: true,
      evolutionApi: evoEnabled,
      evolutionGo: evogoEnabled,
      connect: {
        evolutionApi: evoConnectEnabled,
        evolutionGo: evogoConnectEnabled,
        evolutionApiCreate: evoCreateEnabled,
        evolutionGoCreate: evogoCreateEnabled
      }
    });
  } catch (_e) {
    return res.status(500).json({ ok: false, error: 'DB_UNREACHABLE' });
  }
});

// ── Evolution API (Baileys) — import ─────────────────────────────────────────
// Aceita { instanceName, credsEncoded } (zpro; encode interno feito la) OU
// { instanceName, creds } (UI/manual; dump cru da extensao — encoda aqui).
app.post('/import-creds', requireSecret, async (req, res) => {
  if (!evoPool) {
    return res.status(503).json({ error: 'EVOLUTION_API_NOT_CONFIGURED' });
  }

  const body = req.body || {};
  const instanceName = body.instanceName;

  if (!instanceName || typeof instanceName !== 'string') {
    return res.status(400).json({ error: 'INSTANCE_NAME_REQUIRED' });
  }

  let credsEncoded = body.credsEncoded;
  if (credsEncoded != null) {
    if (typeof credsEncoded !== 'string') {
      return res.status(400).json({ error: 'CREDS_REQUIRED' });
    }
    // Sanidade: credsEncoded deve ser JSON de objeto (BufferJSON) — nao usa reviver.
    try {
      const parsed = JSON.parse(credsEncoded);
      if (!parsed || typeof parsed !== 'object') {
        return res.status(400).json({ error: 'CREDS_INVALID' });
      }
    } catch (_e) {
      return res.status(400).json({ error: 'CREDS_INVALID' });
    }
  } else if (body.creds != null) {
    // Dump cru (Contrato A) — converte pro objeto Baileys e encoda 1x.
    const dump = unwrapDump(body);
    const missing = evoDumpMissing(dump);
    if (missing.length) {
      return res.status(400).json({ error: 'CREDS_INVALID', detail: `faltando: ${missing.join(', ')}` });
    }
    try {
      credsEncoded = buildEvoCredsEncoded(dump);
    } catch (e) {
      return res.status(400).json({ error: 'CREDS_INVALID', detail: (e && e.message) || String(e) });
    }
  } else {
    return res.status(400).json({ error: 'CREDS_REQUIRED' });
  }

  try {
    const sessionId = await writeEvoSession(instanceName, credsEncoded);
    return res.json({ success: true, sessionId });
  } catch (e) {
    if (e && e.code === 'INSTANCE_NOT_FOUND') {
      return res.status(404).json({ error: 'INSTANCE_NOT_FOUND' });
    }
    console.error(`[injector] evo import falhou instance=${instanceName}: ${(e && e.message) || e}`);
    return res.status(500).json({ error: 'IMPORT_FAILED' });
  }
});

// ── Evolution Go (whatsmeow) — import ────────────────────────────────────────
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
    row = buildDeviceRow(unwrapDump(body));
  } catch (e) {
    if (e instanceof CredsError) {
      console.error(`[injector] evogo creds invalidas instance=${instanceId}: ${e.message}`);
      return res.status(400).json({ error: e.code, detail: e.message });
    }
    throw e;
  }

  try {
    const jid = await writeEvoGoDevice(instanceId, row);
    return res.json({ success: true, jid });
  } catch (e) {
    if (e && e.code === 'INSTANCE_NOT_FOUND') {
      return res.status(404).json({ error: 'INSTANCE_NOT_FOUND' });
    }
    console.error(`[injector] evogo import falhou instance=${instanceId}: ${(e && e.message) || e}`);
    return res.status(500).json({ error: 'IMPORT_FAILED' });
  }
});

// ── Listagem de sessoes (p/ a UI escolher) ───────────────────────────────────
app.get('/evo/instances', requireSecret, async (_req, res) => {
  if (!evoPool) return res.status(503).json({ error: 'EVOLUTION_API_NOT_CONFIGURED' });
  try {
    const r = await evoPool.query('SELECT id, name FROM "Instance" ORDER BY name ASC');
    return res.json({ instances: r.rows.map(x => ({ id: x.id, name: x.name })) });
  } catch (e) {
    console.error(`[injector] evo instances falhou: ${(e && e.message) || e}`);
    return res.status(500).json({ error: 'LIST_FAILED' });
  }
});

app.get('/evogo/instances', requireSecret, async (_req, res) => {
  if (!usersPool) return res.status(503).json({ error: 'EVOLUTION_GO_NOT_CONFIGURED' });
  try {
    // Nao devolve o token (fica no servidor); so o que a UI precisa exibir.
    const r = await usersPool.query('SELECT id, name, jid, connected FROM instances ORDER BY name ASC');
    return res.json({
      instances: r.rows.map(x => ({
        id: x.id,
        name: x.name,
        jid: x.jid || null,
        connected: !!x.connected
      }))
    });
  } catch (e) {
    console.error(`[injector] evogo instances falhou: ${(e && e.message) || e}`);
    return res.status(500).json({ error: 'LIST_FAILED' });
  }
});

// ── Criar sessao Evolution API (opcional; exige EVO_API_URL + EVO_API_KEY) ─────
// Identificador da sessao no Evolution e o NOME (import/connect usam o nome).
app.post('/evo/create', requireSecret, async (req, res) => {
  if (!evoCreateEnabled) {
    return res.status(503).json({ error: 'EVO_CREATE_NOT_CONFIGURED' });
  }
  const name = (req.body && req.body.name ? String(req.body.name) : '').trim();
  if (!name) return res.status(400).json({ error: 'NAME_REQUIRED' });
  try {
    const r = await httpJson('POST', `${EVO_API_URL}/instance/create`, {
      apikey: EVO_API_KEY,
      body: { instanceName: name, integration: 'WHATSAPP-BAILEYS' }
    });
    const inst = (r.data && r.data.instance) || {};
    const iname = inst.instanceName || name;
    if (!r.ok || !inst.instanceName) {
      return res.status(502).json({ error: 'CREATE_FAILED', status: r.status, detail: r.data });
    }
    // id = instanceId (informativo); a UI seleciona a sessao pelo NOME.
    return res.json({ success: true, id: inst.instanceId || iname, name: iname });
  } catch (e) {
    console.error(`[injector] evo create falhou name=${name}: ${(e && e.message) || e}`);
    return res.status(502).json({ error: 'CREATE_FAILED', detail: (e && e.message) || String(e) });
  }
});

// ── Criar sessao Evolution Go (opcional; exige EVOGO_API_URL + EVOGO_API_KEY) ──
app.post('/evogo/create', requireSecret, async (req, res) => {
  if (!evogoCreateEnabled) {
    return res.status(503).json({ error: 'EVOGO_CREATE_NOT_CONFIGURED' });
  }
  const name = (req.body && req.body.name ? String(req.body.name) : '').trim();
  if (!name) return res.status(400).json({ error: 'NAME_REQUIRED' });
  try {
    const token = crypto.randomUUID();
    const r = await httpJson('POST', `${EVOGO_API_URL}/instance/create`, {
      apikey: EVOGO_API_KEY,
      body: { name, token }
    });
    const data = (r.data && (r.data.instance || r.data.data)) || r.data || {};
    const id = data.id;
    if (!r.ok || !id) {
      return res.status(502).json({ error: 'CREATE_FAILED', status: r.status, detail: r.data });
    }
    return res.json({ success: true, id, name, token: data.token || token });
  } catch (e) {
    console.error(`[injector] evogo create falhou name=${name}: ${(e && e.message) || e}`);
    return res.status(502).json({ error: 'CREATE_FAILED', detail: (e && e.message) || String(e) });
  }
});

// ── Evolution API — import + connect ao vivo ─────────────────────────────────
app.post('/evo/link', requireSecret, async (req, res) => {
  if (!evoPool) return res.status(503).json({ error: 'EVOLUTION_API_NOT_CONFIGURED' });
  const body = req.body || {};
  const instanceName = body.instanceName;
  if (!instanceName || typeof instanceName !== 'string') {
    return res.status(400).json({ error: 'INSTANCE_NAME_REQUIRED' });
  }

  // 1) creds -> credsEncoded (aceita credsEncoded pronto ou dump cru).
  let credsEncoded = typeof body.credsEncoded === 'string' ? body.credsEncoded : null;
  if (!credsEncoded) {
    const dump = unwrapDump(body);
    const missing = evoDumpMissing(dump);
    if (missing.length) {
      return res.status(400).json({ error: 'CREDS_INVALID', detail: `faltando: ${missing.join(', ')}` });
    }
    try {
      credsEncoded = buildEvoCredsEncoded(dump);
    } catch (e) {
      return res.status(400).json({ error: 'CREDS_INVALID', detail: (e && e.message) || String(e) });
    }
  }

  // 2) grava na Session.
  try {
    await writeEvoSession(instanceName, credsEncoded);
  } catch (e) {
    if (e && e.code === 'INSTANCE_NOT_FOUND') return res.status(404).json({ error: 'INSTANCE_NOT_FOUND' });
    console.error(`[injector] evo link import falhou instance=${instanceName}: ${(e && e.message) || e}`);
    return res.status(500).json({ error: 'IMPORT_FAILED' });
  }

  // 3) connect ao vivo (se configurado). GET /instance/connect/{name} com apikey global.
  if (!evoConnectEnabled) {
    return res.json({
      success: true,
      imported: true,
      connected: false,
      note: 'Creds gravadas. Conexao ao vivo desativada (defina EVO_API_URL + EVO_API_KEY). A sessao sobe no proximo connect/restart do Evolution.'
    });
  }
  try {
    const r = await httpJson('GET', `${EVO_API_URL}/instance/connect/${encodeURIComponent(instanceName)}`, {
      apikey: EVO_API_KEY
    });
    return res.json({
      success: true,
      imported: true,
      connected: r.ok,
      connectStatus: r.status,
      connectBody: r.data
    });
  } catch (e) {
    return res.json({
      success: true,
      imported: true,
      connected: false,
      note: 'Creds gravadas, mas /instance/connect falhou: ' + ((e && e.message) || String(e))
    });
  }
});

// ── Evolution Go — import + connect ao vivo ──────────────────────────────────
app.post('/evogo/link', requireSecret, async (req, res) => {
  if (!authPool || !usersPool) return res.status(503).json({ error: 'EVOLUTION_GO_NOT_CONFIGURED' });
  const body = req.body || {};
  const instanceId = body.instanceId;
  if (!instanceId || typeof instanceId !== 'string') {
    return res.status(400).json({ error: 'INSTANCE_ID_REQUIRED' });
  }

  // 1) valida + monta a linha do device.
  let row;
  try {
    row = buildDeviceRow(unwrapDump(body));
  } catch (e) {
    if (e instanceof CredsError) {
      return res.status(400).json({ error: e.code, detail: e.message });
    }
    throw e;
  }

  // 2) le o token POR-INSTANCIA (necessario p/ o connect) e grava o device.
  let instToken = null;
  try {
    const inst = await usersPool.query('SELECT id, token FROM instances WHERE id = $1', [instanceId]);
    if (!inst.rows.length) return res.status(404).json({ error: 'INSTANCE_NOT_FOUND' });
    instToken = inst.rows[0].token || null;
    await writeEvoGoDevice(instanceId, row);
  } catch (e) {
    if (e && e.code === 'INSTANCE_NOT_FOUND') return res.status(404).json({ error: 'INSTANCE_NOT_FOUND' });
    console.error(`[injector] evogo link import falhou instance=${instanceId}: ${(e && e.message) || e}`);
    return res.status(500).json({ error: 'IMPORT_FAILED' });
  }

  // 3) connect ao vivo (se configurado). POST /instance/connect com apikey = token da instancia.
  if (!evogoConnectEnabled) {
    return res.json({
      success: true,
      imported: true,
      jid: row.jid,
      connected: false,
      note: 'Device gravado. Conexao ao vivo desativada (defina EVOGO_API_URL). A sessao sobe no proximo connect/restart do Evolution Go.'
    });
  }
  if (!instToken) {
    return res.json({
      success: true,
      imported: true,
      jid: row.jid,
      connected: false,
      note: 'Device gravado, mas a instancia nao tem token por-instancia no banco — nao da p/ chamar /instance/connect. A sessao sobe no proximo restart do Evolution Go.'
    });
  }
  try {
    const webhookUrl = body.webhookUrl && typeof body.webhookUrl === 'string' ? body.webhookUrl : '';
    const connectBody = {
      subscribe: webhookUrl ? ['ALL'] : [],
      immediate: true
    };
    if (webhookUrl) connectBody.webhookUrl = webhookUrl;

    const c = await httpJson('POST', `${EVOGO_API_URL}/instance/connect`, {
      apikey: instToken,
      body: connectBody
    });

    // Confirma via /instance/status (mesmo token da instancia).
    let connected = false;
    let statusData = null;
    try {
      const s = await httpJson('GET', `${EVOGO_API_URL}/instance/status`, { apikey: instToken });
      statusData = (s.data && (s.data.data || s.data)) || {};
      connected = !!(statusData.Connected && statusData.LoggedIn);
    } catch (_e) {
      // status transitorio — segue com o resultado do connect.
    }

    return res.json({
      success: true,
      imported: true,
      jid: row.jid,
      connected,
      connectStatus: c.status,
      connectBody: c.data,
      status: statusData
    });
  } catch (e) {
    return res.json({
      success: true,
      imported: true,
      jid: row.jid,
      connected: false,
      note: 'Device gravado, mas /instance/connect falhou: ' + ((e && e.message) || String(e))
    });
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
