/* Ресторан «Тумар»: сервер заявок, календаря, меню и входа в админку.
   Cloudflare Worker + база D1 (привязка с именем DB). Один сайт, отдельно от общего sites-api.
   Заменил Supabase: те же данные (заявки, закрытые даты, меню, объявление), та же логика проверок. */
const SITE = 'tumar';
// sha256("tumar:" + пароль администратора). В боевой версии здесь настоящий хэш, в репозитории — пустышка.
const ADMIN_INIT = '__ADMIN_HASH__';
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Max-Age': '86400'
};
const enc = new TextEncoder();
const J = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { ...CORS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
const E = (m, s = 400) => J({ error: m }, s);
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const sha = async t => hex(await crypto.subtle.digest('SHA-256', enc.encode(t)));
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
function same(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
class HttpErr extends Error { constructor(m, s) { super(m); this.http = s; } }

const kzToday = () => new Date(Date.now() + 5 * 3600e3).toISOString().slice(0, 10); // сегодня по времени Казахстана (UTC+5)
const addDays = (d, n) => new Date(Date.parse(d + 'T00:00:00Z') + n * 864e5).toISOString().slice(0, 10);
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s + 'T00:00:00Z')) && new Date(s + 'T00:00:00Z').toISOString().slice(0, 10) === s;
const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b-\u001f]/g, '').trim().slice(0, n);
const KINDS = ['banquet', 'table'], STATUSES = ['new', 'confirmed', 'cancelled'], KEYS = ['menu', 'notice'];

let ready = false;
async function init(env) {
  if (ready) return;
  await env.DB.batch([
    env.DB.prepare('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)'),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'banquet',
      event_date TEXT NOT NULL, event_time TEXT, guests INTEGER NOT NULL, event_type TEXT, name TEXT NOT NULL, phone TEXT NOT NULL,
      comment TEXT, preorder TEXT, preorder_total INTEGER, source TEXT NOT NULL DEFAULT 'site', status TEXT NOT NULL DEFAULT 'new',
      admin_note TEXT, updated_at TEXT)`),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS bookings_date_idx ON bookings (event_date)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS bookings_phone_idx ON bookings (phone, created_at)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS blocked_dates (date TEXT PRIMARY KEY, reason TEXT, created_at TEXT NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS fails (ip TEXT, t INTEGER)')
  ]);
  ready = true;
}
async function secret(env) {
  const r = await env.DB.prepare("SELECT value FROM meta WHERE key='secret'").first();
  if (r) return r.value;
  const v = crypto.randomUUID() + crypto.randomUUID();
  await env.DB.prepare("INSERT OR IGNORE INTO meta(key,value) VALUES('secret',?)").bind(v).run();
  return (await env.DB.prepare("SELECT value FROM meta WHERE key='secret'").first()).value;
}
async function passHash(env) {
  const r = await env.DB.prepare("SELECT value FROM meta WHERE key='pass_hash'").first();
  return r ? r.value : ADMIN_INIT;
}
async function makeToken(env) {
  const exp = Date.now() + 30 * 864e5;
  return { token: exp + '.' + await hmac(await secret(env), SITE + '|' + exp), exp };
}
async function authed(req, env) {
  const m = (req.headers.get('Authorization') || '').match(/^Bearer (\d+)\.([a-f0-9]{64})$/);
  if (!m || +m[1] < Date.now()) return false;
  return same(await hmac(await secret(env), SITE + '|' + m[1]), m[2]);
}
async function body(req, max) {
  const t = await req.text();
  if (t.length > max) throw new HttpErr('too large', 413);
  try { return t ? JSON.parse(t) : null; } catch (e) { return null; }
}
const needAuth = async (req, env) => { if (!await authed(req, env)) throw new HttpErr('unauthorized', 401); };

// телефон → «+7XXXXXXXXXX» или null
function normPhone(raw) {
  let d = String(raw || '').replace(/\D/g, '');
  if (d.length < 10 || d.length > 15) return null;
  if (d.length === 10) d = '7' + d;
  if (d.length === 11 && d[0] === '8') d = '7' + d.slice(1);
  return '+' + d;
}
// занят ли день: подтверждённый банкет или закрытая вручную дата
async function isBusy(env, date) {
  const a = await env.DB.prepare("SELECT 1 AS x FROM bookings WHERE status='confirmed' AND kind='banquet' AND event_date=? LIMIT 1").bind(date).first();
  if (a) return true;
  const b = await env.DB.prepare('SELECT 1 AS x FROM blocked_dates WHERE date=? LIMIT 1').bind(date).first();
  return !!b;
}

async function route(req, env, url, p) {
  const m = req.method;
  if (p === '/') return J({ ok: true, site: SITE });

  /* ---------- вход ---------- */
  if (p === '/login' && m === 'POST') {
    const ip = req.headers.get('CF-Connecting-IP') || '?', now = Date.now();
    await env.DB.prepare('DELETE FROM fails WHERE t<?').bind(now - 600000).run();
    const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM fails WHERE ip=?').bind(ip).first();
    if (c && c.n >= 8) return E('Слишком много попыток, подождите 10 минут', 429);
    const b = await body(req, 1000), pw = String((b && b.password) || '');
    if (!pw || (await sha(SITE + ':' + pw)) !== await passHash(env)) {
      await env.DB.prepare('INSERT INTO fails(ip,t) VALUES(?,?)').bind(ip, now).run();
      return E('Неверный пароль', 401);
    }
    await env.DB.prepare('DELETE FROM fails WHERE ip=?').bind(ip).run();
    return J(await makeToken(env));
  }
  if (p === '/password' && m === 'POST') {
    await needAuth(req, env);
    const b = await body(req, 500), pw = String((b && b.password) || '');
    if (pw.length < 6 || pw.length > 64) return E('Пароль от 6 до 64 символов');
    await env.DB.prepare("INSERT OR REPLACE INTO meta(key,value) VALUES('pass_hash',?)").bind(await sha(SITE + ':' + pw)).run();
    return J({ ok: true });
  }

  /* ---------- публичное: календарь, меню, новая заявка ---------- */
  if (p === '/busy' && m === 'GET') {
    const today = kzToday();
    let from = url.searchParams.get('from'), to = url.searchParams.get('to');
    if (!isDate(from || '')) from = today;
    if (!isDate(to || '')) to = addDays(today, 400);
    const rs = await env.DB.prepare(`SELECT d FROM (
        SELECT event_date AS d FROM bookings WHERE status='confirmed' AND kind='banquet' AND event_date BETWEEN ?1 AND ?2
        UNION SELECT date AS d FROM blocked_dates WHERE date BETWEEN ?1 AND ?2) ORDER BY d`).bind(from, to).all();
    return J((rs.results || []).map(r => r.d));
  }
  if (p === '/settings' && m === 'GET') {
    const keys = (url.searchParams.get('keys') || KEYS.join(',')).split(',').filter(k => KEYS.includes(k));
    if (!keys.length) return J([]);
    const rs = await env.DB.prepare(`SELECT key, value, updated_at FROM settings WHERE key IN (${keys.map(() => '?').join(',')})`).bind(...keys).all();
    return J((rs.results || []).map(r => { let v = null; try { v = JSON.parse(r.value); } catch (e) {} return { key: r.key, value: v, updated_at: r.updated_at }; }).filter(r => r.value !== null));
  }
  if (p === '/booking' && m === 'POST') {
    const q = await body(req, 20000);
    if (!q || typeof q !== 'object' || Array.isArray(q)) return E('bad request');
    if (clip(q.website, 50)) return J({ ok: true, id: 0 }); // ловушка для спам-ботов
    const kind = q.kind === 'table' ? 'table' : 'banquet';
    const date = clip(q.date, 10), today = kzToday();
    if (!isDate(date)) return J({ ok: false, error: 'Укажите дату' });
    if (date < today) return J({ ok: false, error: 'Эта дата уже прошла' });
    if (date > addDays(today, 730)) return J({ ok: false, error: 'Бронируем не дальше чем на 2 года вперёд' });
    const time = clip(q.time, 5) || null;
    if (time && !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return J({ ok: false, error: 'Время в формате ЧЧ:ММ' });
    const guests = Number(q.guests);
    if (!Number.isInteger(guests) || guests < 1 || guests > 500) return J({ ok: false, error: 'Гостей — от 1 до 500' });
    const name = clip(q.name, 80);
    if (name.length < 2) return J({ ok: false, error: 'Укажите имя' });
    const phone = normPhone(q.phone);
    if (!phone) return J({ ok: false, error: 'Проверьте номер телефона' });
    let total = q.preorder_total === null || q.preorder_total === undefined || q.preorder_total === '' ? null : Number(q.preorder_total);
    if (total !== null && (!Number.isInteger(total) || total < 0 || total > 100000000)) total = null;
    if (await isBusy(env, date)) return J({ ok: false, busy: true, error: 'В этот день зал уже занят — выберите другую дату или позвоните администратору' });
    const since = new Date(Date.now() - 600000).toISOString();
    const same10 = await env.DB.prepare('SELECT COUNT(*) AS n FROM bookings WHERE phone=? AND created_at>?').bind(phone, since).first();
    if (same10 && same10.n >= 3) return J({ ok: false, error: 'Слишком много заявок подряд. Администратор уже получил ваши заявки.' });
    const all10 = await env.DB.prepare("SELECT COUNT(*) AS n FROM bookings WHERE source='site' AND created_at>?").bind(since).first();
    if (all10 && all10.n >= 60) return J({ ok: false, error: 'Сейчас много заявок. Напишите администратору в WhatsApp.' }, 429);
    const r = await env.DB.prepare(`INSERT INTO bookings (created_at, kind, event_date, event_time, guests, event_type, name, phone, comment, preorder, preorder_total, source, status)
      VALUES (?,?,?,?,?,?,?,?,?,?,?, 'site', 'new')`).bind(new Date().toISOString(), kind, date, time, guests, clip(q.type, 60) || null, name, phone,
      clip(q.comment, 1000) || null, String(q.preorder || '').slice(0, 4000) || null, total).run();
    return J({ ok: true, id: r.meta.last_row_id });
  }

  /* ---------- админка (нужен вход) ---------- */
  if (p === '/bookings' && m === 'GET') {
    await needAuth(req, env);
    const rs = await env.DB.prepare('SELECT * FROM bookings ORDER BY event_date ASC, (event_time IS NOT NULL) ASC, event_time ASC, id ASC LIMIT 10000').all();
    return J(rs.results || []);
  }
  if (p === '/bookings' && m === 'POST') { // бронь вручную
    await needAuth(req, env);
    const q = await body(req, 20000);
    if (!q || typeof q !== 'object') return E('bad request');
    const kind = KINDS.includes(q.kind) ? q.kind : 'banquet', status = STATUSES.includes(q.status) ? q.status : 'new';
    const date = clip(q.event_date, 10);
    if (!isDate(date)) return E('Укажите дату');
    const time = clip(q.event_time, 5) || null;
    if (time && !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return E('Время в формате ЧЧ:ММ');
    const guests = Number(q.guests);
    if (!Number.isInteger(guests) || guests < 1 || guests > 500) return E('Гостей — от 1 до 500');
    const name = clip(q.name, 80);
    if (name.length < 2) return E('Укажите имя');
    const phone = normPhone(q.phone);
    if (!phone) return E('Проверьте номер телефона');
    const now = new Date().toISOString();
    const r = await env.DB.prepare(`INSERT INTO bookings (created_at, kind, event_date, event_time, guests, event_type, name, phone, comment, source, status, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?, 'admin', ?, ?)`).bind(now, kind, date, time, guests, clip(q.event_type, 60) || null, name, phone, clip(q.comment, 1000) || null, status, now).run();
    return J({ id: r.meta.last_row_id });
  }
  let mm = p.match(/^\/bookings\/(\d+)$/);
  if (mm && m === 'PATCH') {
    await needAuth(req, env);
    const id = +mm[1], q = await body(req, 2000);
    if (!q || typeof q !== 'object') return E('bad request');
    const sets = [], args = [];
    if ('status' in q) { if (!STATUSES.includes(q.status)) return E('bad status'); sets.push('status=?'); args.push(q.status); }
    if ('admin_note' in q) { sets.push('admin_note=?'); args.push(clip(q.admin_note, 500) || null); }
    if (!sets.length) return E('nothing to update');
    sets.push('updated_at=?'); args.push(new Date().toISOString());
    await env.DB.prepare(`UPDATE bookings SET ${sets.join(', ')} WHERE id=?`).bind(...args, id).run();
    return J({ ok: true });
  }
  if (mm && m === 'DELETE') {
    await needAuth(req, env);
    await env.DB.prepare('DELETE FROM bookings WHERE id=?').bind(+mm[1]).run();
    return J({ ok: true });
  }

  if (p === '/blocked' && m === 'GET') {
    await needAuth(req, env);
    const rs = await env.DB.prepare('SELECT date, reason, created_at FROM blocked_dates ORDER BY date ASC').all();
    return J(rs.results || []);
  }
  if (p === '/blocked' && m === 'POST') {
    await needAuth(req, env);
    const q = await body(req, 1000);
    const date = clip(q && q.date, 10);
    if (!isDate(date)) return E('Укажите дату');
    await env.DB.prepare('INSERT INTO blocked_dates(date,reason,created_at) VALUES(?,?,?) ON CONFLICT(date) DO UPDATE SET reason=excluded.reason')
      .bind(date, clip(q.reason, 200) || null, new Date().toISOString()).run();
    return J({ ok: true });
  }
  mm = p.match(/^\/blocked\/(\d{4}-\d{2}-\d{2})$/);
  if (mm && m === 'DELETE') {
    await needAuth(req, env);
    await env.DB.prepare('DELETE FROM blocked_dates WHERE date=?').bind(mm[1]).run();
    return J({ ok: true });
  }

  mm = p.match(/^\/settings\/(menu|notice)$/);
  if (mm && m === 'PUT') {
    await needAuth(req, env);
    const t = await req.text();
    if (t.length > 600000) return E('too large', 413);
    let v; try { v = JSON.parse(t); } catch (e) { return E('bad json'); }
    if (mm[1] === 'menu' && !Array.isArray(v)) return E('bad data');
    if (mm[1] === 'notice' && (!v || typeof v !== 'object' || Array.isArray(v))) return E('bad data');
    await env.DB.prepare('INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES(?,?,?)').bind(mm[1], JSON.stringify(v), new Date().toISOString()).run();
    return J({ ok: true });
  }
  if (mm && m === 'DELETE') {
    await needAuth(req, env);
    await env.DB.prepare('DELETE FROM settings WHERE key=?').bind(mm[1]).run();
    return J({ ok: true });
  }

  return E('not found', 404);
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const url = new URL(req.url), p = url.pathname.replace(/\/+$/, '') || '/';
    try { await init(env); return await route(req, env, url, p); }
    catch (e) { return e && e.http ? E(e.message, e.http) : E('server error', 500); }
  }
};
