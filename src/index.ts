import { createClient } from '@supabase/supabase-js';
import { launch, type BrowserWorker } from '@cloudflare/playwright';

interface Env {
  BROWSER: BrowserWorker;
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  TIKTOK_BS_ENCRYPTION_KEY: string;
  WORKER_SECRET: string;
  WORKER_ID?: string;
  TIKTOK_BS_ID_MAP?: string;
}

let db: any;
let workerId = 'cloudflare-browser-run';
let encryptionKey = '';
const JOB_TIMEOUT_MS = 100_000;
const STALE_JOB_MS = 4 * 60_000;
let bsIdMap = '{}';
let browserBinding: BrowserWorker;

function configure(env: Env) {
  const required = [
    'SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY',
    'TIKTOK_BS_ENCRYPTION_KEY',
    'WORKER_SECRET'
  ] as const;
  for (const name of required) {
    if (!env[name]) throw new Error(`Missing Worker secret: ${name}`);
  }
  db = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  workerId = env.WORKER_ID || 'cloudflare-browser-run';
  encryptionKey = env.TIKTOK_BS_ENCRYPTION_KEY;
  bsIdMap = env.TIKTOK_BS_ID_MAP || '{}';
  browserBinding = env.BROWSER;
}
const defaultMetrics = [
  'self.pv.number.vv',
  'self.pv.number.vv_increment_value',
  'self.pv.number.vv_increment',
  'self.pv.number.like',
  'self.pv.number.like_increment',
  'self.pv.number.like_increment_value',
  'self.pv.list_daily_like'
];

const SITE_ORIGIN = 'https://datacooker.io.vn';
const SUPABASE_BACKEND =
  'https://uzycjdnivcfnfpjcpubi.supabase.co/functions/v1/datacooker-api';
const securityHeaders = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff'
};

function facebookBinding(request: Request, state: string) {
  if (!/^[a-f0-9]{64}$/.test(state)) return '';
  const value = (request.headers.get('cookie') || '')
    .split(';')
    .map(item => item.trim())
    .find(item => item.startsWith(`dc_fb_${state}=`))
    ?.slice(71) || '';
  return /^[a-f0-9]{64}$/.test(value) ? value : '';
}

function facebookLanding(target: string, state: string, headers: Headers) {
  const nonce = crypto.randomUUID().replaceAll('-', '');
  headers.set('Content-Type', 'text/html; charset=utf-8');
  headers.set(
    'Content-Security-Policy',
    `default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; ` +
      "style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
  );
  const safeTarget = JSON.stringify(target).replaceAll('<', '\\u003c');
  return new Response(
    `<!doctype html><html lang="vi"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kết nối DataCooker</title><style>body{font:16px system-ui;color:#17213d;padding:36px;line-height:1.6}h1{color:#5543dc}button{padding:12px;background:#5543dc;color:white;border:0;border-radius:8px;cursor:pointer}</style><h1>Kết nối Facebook</h1><p id="status">Đang kiểm tra phiên trình duyệt...</p><button id="continue" hidden>Tiếp tục với Facebook</button><noscript>Hãy bật JavaScript để kiểm tra phiên kết nối.</noscript><script nonce="${nonce}">const button=document.getElementById('continue');fetch('/auth/facebook/session-check?state=${state}',{credentials:'same-origin',cache:'no-store'}).then(r=>{if(!r.ok)throw Error();return r.json()}).then(s=>{if(!s.ok)throw Error();document.getElementById('status').textContent='Phiên đã sẵn sàng. Bấm nút bên dưới để cấp quyền.';button.hidden=false;button.onclick=()=>location.replace(${safeTarget});}).catch(()=>{document.getElementById('status').textContent='Trình duyệt chưa lưu được cookie cho datacooker.io.vn. Cho phép cookie của trang này rồi đóng cửa sổ và tạo kết nối mới từ Sidebar.';});</script></html>`,
    { status: 200, headers }
  );
}

async function handleFacebookProxy(request: Request) {
  const url = new URL(request.url);
  const facebookPath = url.pathname.startsWith('/auth/facebook/');
  if (!facebookPath) return null;
  if (request.method !== 'GET') {
    return new Response('Method not allowed', { status: 405, headers: securityHeaders });
  }
  if (url.origin !== SITE_ORIGIN) {
    return new Response('Sai domain kết nối.', { status: 400, headers: securityHeaders });
  }
  if (url.pathname === '/auth/facebook/session-check') {
    const state = url.searchParams.get('state') || '';
    const found = /^[a-f0-9]{64}$/.test(state) && !!facebookBinding(request, state);
    return Response.json({ ok: found }, {
      status: found ? 200 : 400,
      headers: securityHeaders
    });
  }
  const routes: Record<string, string> = {
    '/auth/facebook/launch': '/oauth/facebook/launch',
    '/auth/facebook/callback': '/oauth/facebook/callback'
  };
  const route = routes[url.pathname];
  if (!route) return new Response('Not found', { status: 404, headers: securityHeaders });

  const target = new URL(SUPABASE_BACKEND + route);
  const keys = url.pathname.endsWith('/launch')
    ? ['ticket']
    : ['state', 'code', 'error', 'error_reason'];
  for (const key of keys) {
    if (url.searchParams.has(key)) target.searchParams.set(key, url.searchParams.get(key) || '');
  }
  const upstreamHeaders = new Headers();
  const cookie = (request.headers.get('cookie') || '')
    .split(';')
    .map(item => item.trim())
    .filter(item => /^dc_fb_[a-f0-9]{64}=[a-f0-9]{64}$/.test(item))
    .join('; ');
  if (cookie) upstreamHeaders.set('cookie', cookie);
  const binding = facebookBinding(request, url.searchParams.get('state') || '');
  if (binding) upstreamHeaders.set('x-dc-oauth-binding', binding);

  try {
    const upstream = await fetch(target, { headers: upstreamHeaders, redirect: 'manual' });
    const result = new Headers(securityHeaders);
    const contentType = upstream.headers.get('content-type');
    if (contentType) result.set('content-type', contentType);
    const setCookie =
      upstream.headers.get('x-dc-oauth-set-cookie') ||
      upstream.headers.get('set-cookie') || '';
    if (/^dc_fb_[a-f0-9]{64}=(?:[a-f0-9]{64})?; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=(?:600|0)$/.test(setCookie)) {
      result.set('set-cookie', setCookie);
    }
    const locationValue = upstream.headers.get('location');
    if (locationValue) {
      const location = new URL(locationValue);
      if (location.origin !== 'https://www.facebook.com') throw new Error('redirect');
      const state = location.searchParams.get('state') || '';
      if (!/^[a-f0-9]{64}$/.test(state) || location.pathname !== '/v26.0/dialog/oauth') {
        throw new Error('state');
      }
      if (url.pathname.endsWith('/launch')) {
        if (!result.get('set-cookie')?.startsWith(`dc_fb_${state}=`)) {
          throw new Error('cookie');
        }
        return facebookLanding(location.href, state, result);
      }
      result.set('location', location.href);
    }
    return new Response(upstream.body, { status: upstream.status, headers: result });
  } catch {
    return new Response('Kết nối chưa hoàn tất. Quay lại Sidebar và thử lại.', {
      status: 502,
      headers: securityHeaders
    });
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function withTimeout(promise, timeoutMs, message) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}

function base64Bytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function decryptSession(value) {
  const parts = String(value || '').split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') {
    throw new Error('Encrypted TikTok Session has an invalid format.');
  }
  const keyBytes = base64Bytes(encryptionKey);
  if (keyBytes.length !== 32) throw new Error('Encryption key must contain 32 bytes.');
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
  );
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64Bytes(parts[1]) },
    key,
    base64Bytes(parts[2])
  );
  return new TextDecoder().decode(plain);
}

function cookiePairs(cookieHeader) {
  const ignored = new Set([
    'path', 'domain', 'expires', 'max-age', 'samesite', 'secure', 'httponly'
  ]);
  return String(cookieHeader || '')
    .replace(/^cookie\s*:\s*/i, '')
    .split(';')
    .map(part => part.trim())
    .filter(Boolean)
    .map(part => {
      const at = part.indexOf('=');
      if (at < 1) return null;
      const name = part.slice(0, at).trim();
      const value = part.slice(at + 1).trim();
      if (!name || ignored.has(name.toLowerCase())) return null;
      return {
        name,
        value,
        domain: '.business-suite.tiktok.com',
        path: '/',
        secure: true,
        sameSite: 'Lax' as const
      };
    })
    .filter(Boolean);
}

function collectIds(value, ids, depth = 0) {
  if (depth > 12 || value == null) return;
  if (typeof value === 'string') {
    const patterns = [
      /["'](?:bs_id|business_suite_id)["']\s*[:=]\s*["']?(\d{12,24})/g,
      /(?:[?&]|&amp;)bs_id=(\d{12,24})/g
    ];
    for (const pattern of patterns) {
      for (const match of value.matchAll(pattern)) ids.add(match[1]);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(item => collectIds(item, ids, depth + 1));
    return;
  }
  if (typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (/^(bs_id|business_suite_id)$/i.test(key) && /^\d{12,24}$/.test(String(item))) {
        ids.add(String(item));
      }
      collectIds(item, ids, depth + 1);
    }
  }
}

function collectAdAccounts(value, output, depth = 0) {
  if (depth > 12 || value == null) return;
  if (Array.isArray(value)) {
    value.forEach(item => collectAdAccounts(item, output, depth + 1));
    return;
  }
  if (typeof value !== 'object') return;
  const advertiserId = value.advertiser_id ?? value.ad_account_id ?? value.advertiserId;
  if (advertiserId && /^\d+$/.test(String(advertiserId))) {
    output.set(String(advertiserId), {
      advertiser_id: String(advertiserId),
      advertiser_name: String(
        value.advertiser_name ?? value.ad_account_name ?? value.name ?? ''
      ) || null,
      status: value.status == null ? null : String(value.status),
      currency: value.currency == null ? null : String(value.currency),
      timezone: value.timezone == null ? null : String(value.timezone),
      raw_data: value
    });
  }
  Object.values(value).forEach(item => collectAdAccounts(item, output, depth + 1));
}

function configuredBsIds(businessCenterId) {
  try {
    const map = JSON.parse(bsIdMap);
    const value = map[businessCenterId];
    const values = Array.isArray(value) ? value : String(value || '').split(',');
    return values.map(String).map(v => v.trim()).filter(v => /^\d+$/.test(v));
  } catch {
    throw new Error('TIKTOK_BS_ID_MAP must be valid JSON.');
  }
}

async function discover(context, page, connection) {
  const bsIds = new Set(configuredBsIds(String(connection.business_center_id)));
  const adAccounts = new Map();
  const networkUrls = new Set();
  const metricNames = new Set();
  if (/^\d+$/.test(String(connection.business_suite_id || ''))) {
    bsIds.add(String(connection.business_suite_id));
  }

  page.on('request', request => {
    const url = request.url();
    if (!url.includes('business-suite.tiktok.com')) return;
    networkUrls.add(url.slice(0, 2000));
    collectIds(url, bsIds);
    const body = request.postData();
    if (body) {
      collectIds(body, bsIds);
      try {
        const payload = JSON.parse(body);
        const names = payload?.metric_names;
        if (Array.isArray(names)) names.forEach(name => metricNames.add(String(name)));
      } catch {}
    }
  });

  page.on('response', async response => {
    const url = response.url();
    if (!url.includes('business-suite.tiktok.com')) return;
    const contentType = response.headers()['content-type'] || '';
    if (!contentType.includes('json')) return;
    try {
      const body = await response.text();
      if (body.length > 2_000_000) return;
      collectIds(body, bsIds);
      const parsed = JSON.parse(body);
      collectAdAccounts(parsed, adAccounts);
    } catch {}
  });

  const bcId = encodeURIComponent(String(connection.business_center_id));
  await page.goto(
    `https://business-suite.tiktok.com/insight/overview?org_id=${bcId}`,
    { waitUntil: 'domcontentloaded', timeout: 45000 }
  );
  await page.waitForTimeout(12000);

  const state = await page.evaluate(() => {
    const result = { localStorage: {}, sessionStorage: {}, html: '' };
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key) result.localStorage[key] = localStorage.getItem(key);
    }
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key) result.sessionStorage[key] = sessionStorage.getItem(key);
    }
    result.html = document.documentElement.outerHTML.slice(0, 4_000_000);
    return result;
  });
  collectIds(state, bsIds);
  collectAdAccounts(state, adAccounts);

  if (!bsIds.size) throw new Error('No Business Suite IDs were discovered.');
  return {
    bsIds: [...bsIds],
    adAccounts: [...adAccounts.values()],
    metricNames: metricNames.size ? [...metricNames] : defaultMetrics,
    networkUrls: [...networkUrls],
    state: {
      localStorageKeys: Object.keys(state.localStorage),
      sessionStorageKeys: Object.keys(state.sessionStorage)
    }
  };
}

async function browserJson(page, url, init = {}) {
  return page.evaluate(async ({ url, init }) => {
    const response = await fetch(url, { credentials: 'include', ...init });
    const text = await response.text();
    let body;
    try { body = JSON.parse(text); } catch { body = null; }
    return { ok: response.ok, status: response.status, body };
  }, { url, init });
}

function safeAccount(account) {
  const raw = { ...account };
  for (const key of [
    'sec_uid', 'email', 'mobile', 'phone', 'session', 'cookie',
    'token', 'access_token', 'authorization'
  ]) delete raw[key];
  const id = String(account?.id ?? account?.account_id ?? '').trim();
  if (!id) return null;
  return {
    id,
    uniqueId: String(account?.unique_id ?? '').trim() || null,
    name: String(account?.nickname ?? account?.name ?? '').trim() || null,
    avatar: String(account?.avatar_url ?? account?.avatar ?? '').trim() || null,
    raw
  };
}

async function syncSuite(page, connection, userId, bsId, metricNames) {
  const bcId = String(connection.business_center_id);
  const accountUrl = new URL('https://business-suite.tiktok.com/bs/account/list');
  accountUrl.searchParams.set('bs_id_list', bsId);
  accountUrl.searchParams.set('bc_id', bcId);
  accountUrl.searchParams.set('scene', '3');
  const accountResponse = await browserJson(page, accountUrl.href);
  if (!accountResponse.ok || Number(accountResponse.body?.status_code ?? 0) !== 0) {
    throw new Error(`TikTok account sync failed for BS ${bsId}.`);
  }
  const list = accountResponse.body?.data?.account_list ?? accountResponse.body?.account_list;
  const accounts = (Array.isArray(list) ? list : []).map(safeAccount).filter(Boolean);

  const now = new Date().toISOString();
  let savedAccounts = [];
  if (accounts.length) {
    const { data, error: accountError } = await db
      .from('tiktok_bs_accounts')
      .upsert(accounts.map(account => ({
      user_id: userId,
      connection_id: String(connection.id),
      business_center_id: bcId,
      business_suite_id: bsId,
      account_id: account.id,
      tiktok_account_id: account.id,
      unique_id: account.uniqueId,
      nickname: account.name,
      account_name: account.name,
      account_username: account.uniqueId,
      avatar_url: account.avatar,
      account_status: 'active',
      metadata: account.raw,
      raw_data: account.raw,
      synced_at: now,
      last_sync_at: now,
      updated_at: now
      })), { onConflict: 'connection_id,tiktok_account_id' })
      .select('id,tiktok_account_id');
    if (accountError || !data?.length) {
      throw new Error(accountError?.message || `Could not persist accounts for BS ${bsId}.`);
    }
    savedAccounts = data;
  }

  const endTime = Date.now();
  const startTime = endTime - 60 * 86400000;
  const metricResponse = await browserJson(
    page,
    'https://business-suite.tiktok.com/bs/analytics/query/insights/',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bc_id: bcId,
        bs_id: bsId,
        start_time: String(startTime),
        end_time: String(endTime),
        page_type: 1,
        metric_names: metricNames
      })
    }
  );
  if (!metricResponse.ok || Number(metricResponse.body?.status_code ?? 0) !== 0) {
    throw new Error(`TikTok metrics sync failed for BS ${bsId}.`);
  }
  const metrics = metricResponse.body?.data?.metrics ?? metricResponse.body?.metrics;
  if (!Array.isArray(metrics)) throw new Error(`TikTok returned no metrics for BS ${bsId}.`);

  const metricDate = new Date(endTime).toISOString().slice(0, 10);
  const metricRows = savedAccounts.flatMap(account => metrics.map((metric, index) => {
    const rawValue = metric?.value;
    const numeric = Number(rawValue);
    return {
      user_id: userId,
      connection_id: String(connection.id),
      business_center_id: bcId,
      business_suite_id: bsId,
      account_id: account.id,
      tiktok_account_id: account.tiktok_account_id,
      metric_date: metricDate,
      metric_name: String(metric?.metric_name ?? metric?.name ?? `metric_${index}`),
      metric_value: Number.isFinite(numeric) ? numeric : null,
      metric_data: metric,
      start_time: startTime,
      end_time: endTime,
      value: rawValue ?? null,
      value_map: metric?.value_map ?? null,
      raw_data: metric,
      synced_at: now,
      updated_at: now
    };
  }));
  if (metricRows.length) {
    const { error: metricError } = await db
      .from('tiktok_bs_metrics')
      .upsert(metricRows, { onConflict: 'account_id,metric_date,metric_name' });
    if (metricError) throw new Error(metricError.message);
  }

  const { error: snapshotError } = await db.from('tiktok_bs_metric_snapshots').insert({
    user_id: userId,
    connection_id: String(connection.id),
    business_center_id: bcId,
    business_suite_id: bsId,
    start_time: startTime,
    end_time: endTime,
    page_type: 1,
    metric_count: metrics.length,
    raw_data: metricResponse.body,
    synced_at: now
  });
  if (snapshotError) throw new Error(snapshotError.message);

  const { error: suiteError } = await db.from('tiktok_bs_business_suites').upsert({
    user_id: userId,
    connection_id: String(connection.id),
    business_center_id: bcId,
    business_suite_id: bsId,
    account_count: accounts.length,
    metric_count: metrics.length,
    last_sync_at: now,
    updated_at: now
  }, { onConflict: 'user_id,connection_id,business_suite_id' });
  if (suiteError) throw new Error(suiteError.message);
  return { bsId, accounts: accounts.length, metrics: metrics.length };
}

async function runJob(job) {
  const { data: connection, error } = await db
    .from('tiktok_bs_connections')
    .select('id,user_id,business_center_id,business_suite_id,session_encrypted')
    .eq('id', job.connection_id)
    .eq('user_id', job.user_id)
    .single();
  if (error || !connection) throw new Error('TikTok Business connection was not found.');

  const session = await decryptSession(connection.session_encrypted);
  const browser = await launch(browserBinding, { keep_alive: 120000 });
  try {
    const context = await browser.newContext({
      locale: 'en-US',
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
        'AppleWebKit/537.36 (KHTML, like Gecko) ' +
        'Chrome/124.0.0.0 Safari/537.36'
    });
    const cookies = cookiePairs(session);
    if (!cookies.length) throw new Error('TikTok Session does not contain valid cookies.');
    await context.addCookies(cookies);
    const page = await context.newPage();
    const discovery = await discover(context, page, connection);

    const results = [];
    for (const bsId of discovery.bsIds) {
      results.push(await syncSuite(
        page, connection, String(job.user_id), bsId, discovery.metricNames
      ));
    }

    const now = new Date().toISOString();
    if (discovery.adAccounts.length) {
      const { error: adAccountError } = await db.from('tiktok_bs_ad_accounts').upsert(
        discovery.adAccounts.map(account => ({
          user_id: String(job.user_id),
          connection_id: String(connection.id),
          business_center_id: String(connection.business_center_id),
          business_suite_id: null,
          advertiser_id: account.advertiser_id,
          advertiser_name: account.advertiser_name,
          status: account.status,
          currency: account.currency,
          timezone: account.timezone,
          raw_data: account.raw_data,
          last_sync_at: now,
          updated_at: now
        })),
        { onConflict: 'user_id,connection_id,advertiser_id' }
      );
      if (adAccountError) throw new Error(adAccountError.message);
    }
    const { error: discoveryError } = await db.from('tiktok_bs_discovery_snapshots').insert({
      user_id: String(job.user_id),
      connection_id: String(connection.id),
      business_center_id: String(connection.business_center_id),
      discovered_bs_ids: discovery.bsIds,
      discovered_ad_accounts: discovery.adAccounts,
      network_urls: discovery.networkUrls,
      raw_state: discovery.state
    });
    if (discoveryError) throw new Error(discoveryError.message);

    const { error: connectionError } = await db.from('tiktok_bs_connections').update({
      status: 'active',
      error_message: null,
      last_validated_at: now,
      last_sync_at: now,
      updated_at: now
    }).eq('id', connection.id).eq('user_id', job.user_id);
    if (connectionError) throw new Error(connectionError.message);
    return {
      businessSuiteCount: discovery.bsIds.length,
      adAccountCount: discovery.adAccounts.length,
      results
    };
  } finally {
    await browser.close();
  }
}

async function finishJob(job, result) {
  const now = new Date().toISOString();
  const { error } = await db.from('tiktok_bs_sync_jobs').update({
    status: 'completed',
    result,
    error_message: null,
    finished_at: now,
    updated_at: now
  }).eq('id', job.id).eq('locked_by', workerId);
  if (error) throw new Error(`Could not complete job ${job.id}: ${error.message}`);
}

async function failJob(job, error) {
  const message = String(error?.message || error || 'TikTok sync failed').slice(0, 1000);
  const retry = Number(job.attempt_count || 0) < 3;
  const now = new Date().toISOString();
  await db.from('tiktok_bs_sync_jobs').update({
    status: retry ? 'pending' : 'failed',
    available_at: retry ? new Date(Date.now() + 60_000).toISOString() : now,
    locked_at: null,
    locked_by: null,
    error_message: message,
    finished_at: retry ? null : now,
    updated_at: now
  }).eq('id', job.id);
  await db.from('tiktok_bs_connections').update({
    status: retry ? 'pending' : 'error',
    error_message: message,
    updated_at: now
  }).eq('id', job.connection_id).eq('user_id', job.user_id);
}

async function recoverStaleJobs() {
  const staleBefore = new Date(Date.now() - STALE_JOB_MS).toISOString();
  const now = new Date().toISOString();
  const { error } = await db.from('tiktok_bs_sync_jobs').update({
    status: 'pending',
    available_at: now,
    locked_at: null,
    locked_by: null,
    error_message: 'Previous Browser Run timed out and was queued again.',
    started_at: null,
    finished_at: null,
    updated_at: now
  }).eq('status', 'processing').lt('locked_at', staleBefore);
  if (error) throw new Error(`Could not recover stale jobs: ${error.message}`);
}

async function runOneJob(env: Env) {
  configure(env);
  await recoverStaleJobs();
  const { data, error } = await db.rpc('dc_claim_tiktok_bs_sync_job', {
    p_worker: workerId
  });
  if (error) throw new Error(`Queue error: ${error.message}`);
  const job = data?.[0];
  if (!job) return { ok: true, claimed: false };

  try {
    const result = await withTimeout(
      runJob(job),
      JOB_TIMEOUT_MS,
      `TikTok Browser Run exceeded ${JOB_TIMEOUT_MS / 1000} seconds.`
    );
    await finishJob(job, result);
    return { ok: true, claimed: true, jobId: job.id, result };
  } catch (error) {
    console.error(`Job ${job.id} failed`, error);
    await failJob(job, error);
    return {
      ok: false,
      claimed: true,
      jobId: job.id,
      error: String(error?.message || error)
    };
  }
}

export default {
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(runOneJob(env));
  },

  async fetch(request: Request, env: Env) {
    const facebookResponse = await handleFacebookProxy(request);
    if (facebookResponse) return facebookResponse;

    const url = new URL(request.url);
    if (url.pathname === '/health') {
      return Response.json({ ok: true, service: 'datacooker-tiktok-bs-sync' });
    }
    if (url.pathname === '/' && request.method === 'GET') {
      return new Response(
        `<!doctype html><html lang="vi"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DataCooker</title><style>body{font:18px system-ui;background:#f3f5fc;color:#18213b;margin:0;padding:10vh 8vw}main{max-width:720px;margin:auto;background:white;padding:48px;border-radius:20px}h1{color:#5141df}p{line-height:1.7}</style><main><h1>DataCooker</h1><h2>Dữ liệu Facebook trong Google Sheets</h2><p>Mở Sidebar DataCooker trong Google Sheets, chọn <strong>Kết nối / cấp quyền lại Facebook</strong> để kết nối đúng tài khoản DataCooker của bạn.</p><p>Sau khi bạn xác nhận quyền trên Facebook, hệ thống tự nhận và lưu token. Bạn không cần sao chép token thủ công.</p></main></html>`,
        {
          headers: {
            ...securityHeaders,
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Security-Policy':
              "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
          }
        }
      );
    }
    if (url.pathname !== '/run' || request.method !== 'POST') {
      return new Response('Not found', { status: 404 });
    }
    const authorization = request.headers.get('Authorization') || '';
    if (authorization !== `Bearer ${env.WORKER_SECRET}`) {
      return new Response('Unauthorized', { status: 401 });
    }
    try {
      return Response.json(await runOneJob(env));
    } catch (error) {
      console.error(error);
      return Response.json(
        { ok: false, error: String(error?.message || error) },
        { status: 500 }
      );
    }
  }
} satisfies ExportedHandler<Env>;
