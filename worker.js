// VERSION: 1.2.3

// ==========================================
// 安全工具函数 (Security Utilities)
// ==========================================

// XSS防护：HTML实体转义
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const str = String(text);
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// URL验证
function isValidUrl(urlStr) {
    try {
        if (!urlStr) return false;
        const url = new URL(urlStr);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch(e) {
        return false;
    }
}

// ==========================================
// 🌟 Cloudflare 优选域名库（借鉴 EMBY_CF 的 OPTIMIZED_DOMAINS）
// 一份社区维护的 CF 优选域名清单，由 Worker 边缘/浏览器双端测速取最快。
// 这些域名本身不是「IP 库」，而是作为优选入口；实际优选 IP 由测速得出。
// ==========================================
const OPTIMIZED_DOMAINS = [
  { subdomain: 'proxy1', domain: 'cf.090227.xyz', name: 'CF优选-090227' },
  { subdomain: 'proxy2', domain: 'cf.877774.xyz', name: 'CF优选-877774' },
  { subdomain: 'proxy3', domain: 'cloudflare-dl.byoip.top', name: '鱼皮优选' },
  { subdomain: 'proxy4', domain: 'saas.sin.fan', name: 'MIYU优选' },
  { subdomain: 'proxy5', domain: 'bestcf.030101.xyz', name: 'Mingyu优选' },
  { subdomain: 'proxy6', domain: 'cf.cloudflare.182682.xyz', name: 'WeTest优选' },
  { subdomain: 'proxy7', domain: 'cf.tencentapp.cn', name: '腾讯泛域名' },
  { subdomain: 'proxy8', domain: 'www.visa.cn', name: 'Visa官方' },
  { subdomain: 'proxy9', domain: 'mfa.gov.ua', name: '乌克兰外交部' },
  { subdomain: 'proxy10', domain: 'www.shopify.com', name: 'Shopify官方' },
  { subdomain: 'proxy11', domain: 'store.ubi.com', name: '育碧商店' },
  { subdomain: 'proxy12', domain: 'staticdelivery.nexusmods.com', name: 'NexusMods' },
];

// 客户端网段缓存 key：IPv4 取 /24，IPv6 取完整，未知回落 default
function getClientCacheKey(ip) {
    if (!ip || ip === 'Unknown') return 'default';
    if (ip.includes(':')) return ip;
    const parts = ip.split('.');
    if (parts.length === 4) return parts.slice(0, 3).join('.');
    return ip;
}

// 边缘节点对所有优选域名发 HEAD /cdn-cgi/trace 测速，按延迟排序返回
async function speedtestOptimizedFromEdge() {
    const tasks = OPTIMIZED_DOMAINS.map(async (d) => {
        const host = d.subdomain + '.' + d.domain;
        const start = Date.now();
        try {
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), 4000);
            const r = await fetch(`https://${host}/cdn-cgi/trace`, { method: 'HEAD', signal: ctrl.signal });
            clearTimeout(timer);
            const ms = Date.now() - start;
            return { host, name: d.name, ms: r.ok ? ms : 9999, ok: r.ok };
        } catch (e) {
            return { host, name: d.name, ms: 9999, ok: false };
        }
    });
    const results = await Promise.all(tasks);
    results.sort((a, b) => a.ms - b.ms);
    return results;
}

// ==========================================
// 🔀 运行时故障转移（Failover）共享缓存与配置
// ==========================================
// 模块级缓存（同 isolate 内跨请求共享，冷启动重置；配合 D1 持久化跨 isolate 可见）
const FD = globalThis.__fd || (globalThis.__fd = { health: new Map(), cfg: new Map(), cfgUntil: 0 });
const FO_DOWN_TTL = 60 * 1000; // 节点判定为「不可用」后的跳过时长（秒级切换）

// 读取系统配置（30s 内存缓存，避免每请求打 D1；未命中的 key 不缓存，保证写入后立即可读）
async function getCfg(env, key, defVal) {
    const now = Date.now();
    if (FD.cfgUntil > now - 30000 && FD.cfg.has(key)) return FD.cfg.get(key);
    let val = defVal; let found = false;
    try {
        const row = await env.DB.prepare('SELECT value FROM system_config WHERE key = ?').bind(key).first();
        if (row && row.value != null) { val = row.value; found = true; }
    } catch (e) {}
    if (found) { FD.cfg.set(key, val); FD.cfgUntil = now; }
    return val;
}

async function setCfg(env, key, value) {
    try {
        await env.DB.prepare('INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)').bind(key, String(value)).run();
        FD.cfg.set(key, String(value)); FD.cfgUntil = Date.now();
        return true;
    } catch (e) { return false; }
}

// 标记节点健康状态（内存 + D1）
function markNodeDown(targetUrlStr) {
    FD.health.set(targetUrlStr, Date.now() + FO_DOWN_TTL);
    try { globalThis.__fdDB && globalThis.__fdDB.prepare('INSERT OR REPLACE INTO node_health (target, status, ts) VALUES (?, ?, ?)').bind(targetUrlStr, 'down', Date.now()).run(); } catch (e) {}
}
function markNodeUp(targetUrlStr) {
    FD.health.delete(targetUrlStr);
}
function isNodeDown(targetUrlStr) {
    const until = FD.health.get(targetUrlStr);
    if (!until) return false;
    if (until < Date.now()) { FD.health.delete(targetUrlStr); return false; }
    return true;
}
// 记录一次故障转移事件并累加当日计数
async function logFailover(env, prefix, targetUrlStr, reason) {
    try {
        const today = new Date(Date.now() + 8 * 3600000).toISOString().split('T')[0];
        await env.DB.prepare('INSERT INTO failover_log (prefix, target, ts, reason) VALUES (?, ?, ?, ?)')
            .bind(prefix || 'direct', targetUrlStr, Date.now(), reason || '').run();
        const row = await env.DB.prepare('SELECT value FROM system_config WHERE key = ?').bind('failover_' + today).first();
        const n = (row && row.value) ? parseInt(row.value, 10) || 0 : 0;
        await env.DB.prepare('INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)').bind('failover_' + today, String(n + 1)).run();
    } catch (e) {}
}


// 路径验证：防止路径遍历攻击
function isValidPath(path) {
    if (!path) return false;
    if (path.includes('../') || path.includes('..\\') || path.includes('\0')) return false;
    return true;
}

// 安全JSON解析
function safeJsonParse(str, fallback = null) {
    try {
        return JSON.parse(str);
    } catch(e) {
        console.warn('JSON parse failed:', e.message);
        return fallback;
    }
}

// 带重试的fetch请求
async function fetchWithRetry(url, options = {}, retries = 3, delayMs = 1000) {
    let lastError;
    for (let i = 0; i < retries; i++) {
        try {
            const res = await fetch(url, options);
            if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            return res;
        } catch(e) {
            lastError = e;
            if (i < retries - 1) {
                await new Promise(resolve => setTimeout(resolve, delayMs * (i + 1)));
            }
        }
    }
    throw lastError;
}

// ==========================================
// 1. 网页界面-单播报版本
// ==========================================

const SVG_EYE = `<svg viewBox="0 0 24 24"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>`;
const SVG_COPY = `<svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>`;
const SVG_TG = `<svg viewBox="0 0 24 24" style="width:20px;height:20px;margin-right:8px;fill:#0088cc;"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.446 1.394c-.14.18-.357.295-.6.295-.002 0-.003 0-.005 0l.213-3.054 5.56-5.022c.24-.213-.054-.334-.373-.121l-6.869 4.326-2.96-.924c-.64-.203-.658-.64.135-.954l11.566-4.458c.538-.196 1.006.128.832.94z"/></svg>`;

const CSS_COMMON = `
    :root {
        --primary: #10b981;
        --primary-hover: #059669;
        --primary-end: #14b8a6;
        --bg: #f8f9fb;
        --card: rgba(255,255,255,0.72);
        --card-solid: #ffffff;
        --text: #111827;
        --text-sec: #6b7280;
        --border: rgba(0,0,0,0.06);
        --border-solid: #e5e7eb;
        --radius-card: 16px;
        --shadow-card: 0 1px 3px rgba(0,0,0,0.04), 0 4px 24px rgba(0,0,0,0.03);
        --shadow-hover: 0 8px 32px rgba(16,185,129,0.1), 0 2px 8px rgba(0,0,0,0.04);
        --glass-bg: rgba(255,255,255,0.6);
        --glass-border: rgba(255,255,255,0.3);
        --success: #22c55e;
        --warning: #f59e0b;
        --danger: #ef4444;
        --info: #3b82f6;
        --nav-height: 60px;
    }

    body.dark {
        --primary: #34d399;
        --primary-hover: #10b981;
        --primary-end: #5eead4;
        --bg: #0b1120;
        --card: rgba(17,25,35,0.72);
        --card-solid: #131c26;
        --text: #f3f4f6;
        --text-sec: #9ca3af;
        --border: rgba(255,255,255,0.07);
        --border-solid: #243140;
        --shadow-card: 0 1px 3px rgba(0,0,0,0.25), 0 4px 24px rgba(0,0,0,0.2);
        --shadow-hover: 0 8px 32px rgba(52,211,153,0.18), 0 2px 8px rgba(0,0,0,0.25);
        --glass-bg: rgba(13,20,30,0.6);
        --glass-border: rgba(255,255,255,0.08);
    }

    * { box-sizing: border-box; touch-action: manipulation; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 0; -webkit-text-size-adjust: 100%; transition: background-color 0.4s ease, color 0.3s ease; line-height: 1.6; }
    .container { max-width: 1200px; margin: 0 auto; width: 100%; min-height: 100vh; display: flex; flex-direction: column; padding: 0 20px; padding-top: calc(var(--nav-height) + 20px); }
    .content-wrap { flex: 1; }
    input, select, button, textarea { font-family: inherit; outline: none; font-size: 14px; }

    .card { background: var(--card); padding: 24px; border-radius: var(--radius-card); box-shadow: var(--shadow-card); margin-bottom: 20px; border: 1px solid var(--border); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); transition: box-shadow 0.3s ease, transform 0.3s ease, border-color 0.3s ease; }

    #toast { position: fixed; top: -60px; left: 50%; transform: translateX(-50%); background: var(--card-solid); color: var(--text); padding: 12px 24px; border-radius: 12px; font-size: 14px; font-weight: 500; transition: top 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); z-index: 99999; backdrop-filter: blur(20px); text-align: center; max-width: 90vw; word-wrap: break-word; box-shadow: 0 8px 32px rgba(0,0,0,0.12); border: 1px solid var(--border); }
    body.dark #toast { background: #1e1e1e; }
    #toast.show { top: 20px; }

    .top-nav { position: fixed; top: 0; left: 0; right: 0; height: var(--nav-height); background: var(--glass-bg); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px); border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 24px; z-index: 9999; transition: background 0.3s ease; }
    .nav-left { display: flex; align-items: center; gap: 12px; flex: 1; min-width: 0; }
    .nav-brand { font-size: 16px; font-weight: 700; background: linear-gradient(135deg, var(--primary), var(--primary-end)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; white-space: nowrap; flex-shrink: 0; }
    .nav-version { font-size: 11px; color: var(--text-sec); background: var(--border); padding: 2px 8px; border-radius: 6px; font-weight: 500; white-space: nowrap; flex-shrink: 0; }
    .nav-trace { display: flex; align-items: center; gap: 16px; margin-left: 16px; padding-left: 16px; border-left: 1px solid var(--border); font-size: 12px; flex-wrap: wrap; }
    .nav-trace-item { display: flex; align-items: center; gap: 6px; white-space: nowrap; }
    .nav-trace-icon { font-size: 14px; }
    .nav-trace-label { color: var(--text-sec); font-size: 11px; }
    .nav-trace-value { font-weight: 600; font-family: "SF Mono", monospace; font-size: 12px; }
    .nav-trace-value.success { color: var(--success); }
    .nav-right { display: flex; align-items: center; gap: 10px; }
    .nav-rtt { display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; padding: 6px 12px; border-radius: 8px; background: var(--border); }
    .nav-rtt-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--success); box-shadow: 0 0 6px var(--success); transition: 0.3s; }
    .nav-rtt-value { font-family: "SF Mono", monospace; font-size: 12px; min-width: 50px; text-align: right; }
    .nav-btn { display: inline-flex; align-items: center; gap: 6px; padding: 7px 14px; border-radius: 8px; border: 1px solid var(--border); background: transparent; color: var(--text); cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.2s ease; white-space: nowrap; }
    .nav-btn:hover { background: var(--border); }
    .nav-btn-primary { background: linear-gradient(135deg, var(--primary), var(--primary-end)); color: white; border: none; }
    .nav-btn-primary:hover { opacity: 0.9; box-shadow: 0 4px 12px rgba(16,185,129,0.3); }
    .nav-btn-danger { color: var(--danger); border-color: rgba(239,68,68,0.2); }
    .nav-btn-danger:hover { background: rgba(239,68,68,0.08); }
    .nav-theme-btn { width: 36px; height: 36px; padding: 0; display: flex; align-items: center; justify-content: center; font-size: 18px; border-radius: 10px; }

    .toolbar { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; align-items: center; }
    .btn-submit { padding: 10px 18px; background: linear-gradient(135deg, var(--primary), var(--primary-end)); color: white; border: none; border-radius: 10px; cursor: pointer; font-weight: 600; font-size: 13px; white-space: nowrap; transition: all 0.25s ease; box-shadow: 0 2px 8px rgba(16,185,129,0.25); }
    .btn-submit:hover { transform: translateY(-1px); box-shadow: 0 4px 16px rgba(16,185,129,0.35); }
    .btn-submit:active { transform: translateY(0); }
    .btn-submit:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
    .btn-outline { padding: 10px 18px; background: transparent; color: var(--text); border: 1px solid var(--border-solid); border-radius: 10px; cursor: pointer; font-weight: 500; font-size: 13px; white-space: nowrap; transition: all 0.2s ease; }
    .btn-outline:hover { background: var(--border); border-color: var(--primary); color: var(--primary); }
    .btn-danger { padding: 10px 18px; background: var(--danger); color: white; border: none; border-radius: 10px; cursor: pointer; font-weight: 600; font-size: 13px; white-space: nowrap; transition: all 0.2s ease; box-shadow: 0 2px 8px rgba(239,68,68,0.2); }
    .btn-danger:hover { box-shadow: 0 4px 16px rgba(239,68,68,0.3); }

    .table-wrapper { width: 100%; border-radius: 12px; border: 1px solid var(--border); overflow: hidden; background: var(--card); backdrop-filter: blur(20px); }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th, td { padding: 14px 16px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: middle; }
    th { color: var(--text-sec); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; background: rgba(120,120,120,0.03); }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background-color: rgba(16,185,129,0.03); }

    .action-group { display: inline-flex; gap: 6px; background: rgba(120,120,120,0.04); padding: 4px 8px; border-radius: 8px; border: 1px solid var(--border); align-items: flex-start; max-width: 100%; flex-wrap: wrap; }
    .icon-btn { display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 8px; border: none; background: transparent; cursor: pointer; color: var(--text-sec); padding: 0; transition: all 0.2s ease; flex-shrink: 0; font-size: 16px; }
    .icon-btn:hover { color: var(--primary); background: rgba(16,185,129,0.08); }
    .icon-btn svg { width: 15px; height: 15px; fill: currentColor; }

    .badge { padding: 3px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; display: inline-block; letter-spacing: 0.3px; }

    .btn-edit { padding: 7px 14px; background: transparent; color: var(--primary); border: 1px solid rgba(16,185,129,0.3); border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 600; transition: all 0.2s ease; }
    .btn-edit:hover { background: rgba(16,185,129,0.08); border-color: var(--primary); }
    .btn-del { padding: 7px 14px; background: transparent; color: var(--danger); border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 600; transition: all 0.2s ease; }
    .btn-del:hover { background: rgba(239,68,68,0.08); border-color: var(--danger); }
    .btn-dns { padding: 7px 14px; background: transparent; color: var(--success); border: 1px solid rgba(34,197,94,0.3); border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 600; transition: all 0.2s ease; white-space: nowrap; }
    .btn-dns:hover { background: rgba(34,197,94,0.08); border-color: var(--success); }
    .btn-dns:disabled { opacity: 0.4; cursor: not-allowed; }

    .ip-checkbox { width: 16px; height: 16px; cursor: pointer; accent-color: var(--primary); border-radius: 4px; }
    .secret-text { font-family: "SF Mono", "Fira Code", monospace; letter-spacing: 2px; color: var(--text-sec); }

    .dynamic-url { display: block; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; text-align: right; }
    .actual-text.dynamic-url { white-space: normal; max-width: 100%; overflow: visible; text-align: left !important; word-break: break-all; font-size: 13px; font-family: "SF Mono", monospace; color: var(--primary); letter-spacing: normal; }
    .url-list-item { background: var(--border); padding: 4px 8px; border-radius: 6px; font-size: 12px; margin-top: 6px; word-break: break-all; line-height: 1.4; color: var(--text); font-family: -apple-system, sans-serif; letter-spacing: normal; text-align: left; }
    .url-list-item:first-child { margin-top: 0; }

    body.dark input, body.dark select, body.dark textarea { background: #1a1a1a; color: #f3f4f6; border: 1px solid #2a2a2a; }

    .search-input { padding: 9px 14px; border: 1px solid var(--border-solid); border-radius: 10px; background: var(--card-solid); color: var(--text); font-size: 13px; width: 240px; transition: all 0.3s ease; }
    body.dark .search-input { background: #1a1a1a; }
    .search-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(16,185,129,0.12); }

    .node-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 16px; margin-top: 16px; }
    .emby-card { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius-card); padding: 20px; box-shadow: var(--shadow-card); display: flex; flex-direction: column; gap: 14px; transition: all 0.3s ease; position: relative; backdrop-filter: blur(20px); }
    .emby-card:hover { box-shadow: var(--shadow-hover); transform: translateY(-2px); border-color: rgba(16,185,129,0.15); }
    .card-header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid var(--border); padding-bottom: 14px; }
    .card-title-group { display: flex; align-items: center; gap: 10px; }
    .emby-icon { font-size: 24px; background: linear-gradient(135deg, rgba(16,185,129,0.08), rgba(139,92,246,0.08)); border-radius: 10px; padding: 8px; border: 1px solid rgba(16,185,129,0.1); display: flex; align-items: center; justify-content: center; width: 40px; height: 40px; flex-shrink: 0; }
    .info-row { display: flex; align-items: flex-start; justify-content: space-between; font-size: 13px; }
    .info-label { color: var(--text-sec); font-weight: 500; min-width: 65px; margin-top: 2px; font-size: 12px; }
    .card-footer { display: flex; justify-content: flex-end; gap: 8px; margin-top: auto; padding-top: 14px; border-top: 1px solid var(--border); }

    .ping-badge { color: var(--text-sec); cursor: pointer; padding: 3px 10px; background: rgba(120,120,120,0.04); border-radius: 6px; font-size: 12px; font-weight: 600; transition: all 0.2s ease; border: 1px solid transparent; user-select: none; font-family: "SF Mono", monospace; }
    .ping-badge:hover { border-color: var(--primary); background: rgba(16,185,129,0.06); color: var(--primary); }

    .icon-item { cursor: pointer; padding: 6px; border-radius: 10px; border: 1px solid transparent; display: flex; justify-content: center; align-items: center; transition: all 0.2s ease; background: var(--border); height: 44px; }
    .icon-item:hover { border-color: var(--primary) !important; box-shadow: 0 2px 8px rgba(16,185,129,0.2); transform: scale(1.05); }
    #iconGrid::-webkit-scrollbar { width: 4px; }
    #iconGrid::-webkit-scrollbar-thumb { background: var(--border-solid); border-radius: 2px; }

    .emby-card.sortable-ghost { opacity: 0.4; }
    .emby-card.sortable-drag { cursor: grabbing !important; }
    .drag-handle { cursor: grab; padding-right: 8px; font-size: 16px; color: var(--text-sec); display: flex; align-items: center; user-select: none; touch-action: none; opacity: 0.5; transition: opacity 0.2s; }
    .drag-handle:hover { opacity: 1; }
    .drag-handle:active { cursor: grabbing; color: var(--primary); }

    .section-title { font-size: 16px; font-weight: 700; margin: 0; display: flex; align-items: center; gap: 8px; }
    .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }
    .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
    .stat-item { text-align: center; padding: 12px 8px; border-radius: 10px; background: rgba(120,120,120,0.03); }
    .stat-label { font-size: 11px; color: var(--text-sec); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500; }
    .stat-value { font-size: 16px; font-weight: 700; }
    .stat-value.success { color: var(--success); }
    .stat-value.primary { color: var(--primary); }

    .info-panel { background: rgba(120,120,120,0.03); padding: 14px 16px; border-radius: 12px; border: 1px solid var(--border); }
    .info-panel-label { font-size: 12px; font-weight: 600; color: var(--text-sec); margin-bottom: 8px; }

    .form-input { padding: 10px 14px; border: 1px solid var(--border-solid); border-radius: 10px; background: var(--card-solid); color: var(--text); transition: all 0.2s ease; }
    body.dark .form-input { background: #1a1a1a; }
    .form-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(16,185,129,0.1); }

    .node-stats { background: rgba(16,185,129,0.04); border: 1px solid rgba(16,185,129,0.08); border-radius: 10px; padding: 12px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 10px; }
    .node-stat-item { display: flex; flex-direction: column; gap: 2px; }
    .node-stat-label { font-size: 11px; color: var(--text-sec); }
    .node-stat-value { font-size: 15px; font-weight: 700; }

    .node-details { margin-top: 2px; }
    .node-details summary { list-style: none; cursor: pointer; font-size: 13px; color: var(--primary); font-weight: 600; padding: 6px 0; user-select: none; display: flex; align-items: center; gap: 6px; }
    .node-details summary::-webkit-details-marker { display: none; }
    .node-details summary::before { content: '▸'; transition: transform 0.2s ease; color: var(--primary); }
    .node-details[open] summary::before { transform: rotate(90deg); }
    .node-details-body { display: flex; flex-direction: column; gap: 12px; padding-top: 10px; }

    .batch-bar { background: rgba(16,185,129,0.04); padding: 12px 16px; border-radius: 12px; border: 1px dashed rgba(16,185,129,0.2); margin-bottom: 16px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .batch-divider { width: 1px; height: 20px; background: var(--border-solid); }

    .status-msg { line-height: 1.6; font-size: 13px; color: var(--text-sec); padding: 12px 16px; border-radius: 10px; border-left: 3px solid var(--success); background: rgba(34,197,94,0.04); }

    .alert-card { border-left: 3px solid var(--success); }
    .alert-card.danger { border-left-color: var(--danger); }

    .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 10000; overflow-y: auto; padding: 20px; backdrop-filter: blur(8px); }
    .modal-card { max-width: 1000px; margin: 40px auto; position: relative; background: var(--card-solid); border-radius: var(--radius-card); box-shadow: 0 24px 80px rgba(0,0,0,0.15); border: 1px solid var(--border); }
    body.dark .modal-card { background: #1a1a1a; }
    .modal-close { position: absolute; top: 16px; right: 16px; width: 32px; height: 32px; border-radius: 8px; border: none; background: transparent; cursor: pointer; color: var(--text-sec); font-size: 18px; display: flex; align-items: center; justify-content: center; transition: all 0.2s ease; }
    .modal-close:hover { background: rgba(239,68,68,0.08); color: var(--danger); }
    .modal-header { padding: 24px 24px 0; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; }
    .modal-title { display: flex; align-items: center; gap: 10px; font-size: 18px; font-weight: 700; }
    .modal-title-sub { font-size: 13px; font-weight: normal; color: var(--text-sec); }
    .modal-traffic-bar { font-size: 12px; background: rgba(16,185,129,0.06); color: var(--primary); padding: 6px 14px; border-radius: 8px; border: 1px solid rgba(16,185,129,0.1); display: flex; gap: 16px; flex-wrap: wrap; font-weight: 500; }
    .modal-body { padding: 20px 24px 24px; }
    .chart-row { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 20px; }
    .chart-col { border: 1px solid var(--border); border-radius: 12px; padding: 16px; background: rgba(120,120,120,0.02); }
    .chart-col-main { flex: 2; min-width: 300px; }
    .chart-col-side { flex: 1; min-width: 280px; display: flex; justify-content: center; align-items: center; }
    .dashboard-charts { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 16px; }
    .dash-card { border: 1px solid var(--border); border-radius: 12px; padding: 14px; background: rgba(120,120,120,0.02); display: flex; flex-direction: column; }
    .dash-card-title { font-size: 13px; color: var(--text-sec); font-weight: 500; margin-bottom: 8px; white-space: nowrap; display: flex; align-items: center; gap: 6px; }
    .dash-card-body { flex: 1; min-height: 0; position: relative; }
    .dash-card-body canvas, .dash-card-body > div { width: 100% !important; height: 100% !important; }
    .modal-section-title { margin-top: 24px; margin-bottom: 14px; font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
    .modal-section-sub { font-size: 11px; color: var(--text-sec); font-weight: normal; }

    .footer { text-align: center; padding: 20px 0; }
    .footer-text { font-size: 11px; color: var(--text-sec); line-height: 1.6; max-width: 600px; margin: 0 auto; padding: 0 15px; }

    /* Telegram 机器人控制台 */
    .tg-console { }
    .tg-console-header { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
    .tg-console-icon { width: 32px; height: 32px; background: linear-gradient(135deg, #0088cc, #00a8e6); border-radius: 8px; display: flex; align-items: center; justify-content: center; color: white; font-size: 18px; }
    .tg-console-title { font-size: 16px; font-weight: 700; }
    .tg-console-desc { font-size: 12px; color: var(--text-sec); margin-bottom: 16px; }
    .tg-tags { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
    .tg-tag { padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; background: rgba(0,136,204,0.08); color: #0088cc; border: 1px solid rgba(0,136,204,0.15); }
    .tg-tag.success { background: rgba(34,197,94,0.08); color: var(--success); border-color: rgba(34,197,94,0.15); }
    .tg-tag.warn { background: rgba(245,158,11,0.08); color: var(--warning); border-color: rgba(245,158,11,0.15); }
    
    /* Bot推送开关 */
    .tg-toggle { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; padding: 10px 14px; background: rgba(120,120,120,0.03); border-radius: 10px; border: 1px solid var(--border); }
    .tg-toggle-label { font-size: 13px; font-weight: 600; flex: 1; }
    .tg-toggle-switch { position: relative; width: 44px; height: 24px; cursor: pointer; }
    .tg-toggle-switch input { opacity: 0; width: 0; height: 0; }
    .tg-toggle-slider { position: absolute; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; border-radius: 24px; transition: 0.3s; }
    .tg-toggle-slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; border-radius: 50%; transition: 0.3s; }
    .tg-toggle-switch input:checked + .tg-toggle-slider { background-color: var(--success); }
    .tg-toggle-switch input:checked + .tg-toggle-slider:before { transform: translateX(20px); }
    .tg-toggle-status { font-size: 12px; font-weight: 600; padding: 3px 8px; border-radius: 6px; }
    .tg-toggle-status.on { background: rgba(34,197,94,0.08); color: var(--success); }
    .tg-toggle-status.off { background: rgba(239,68,68,0.08); color: var(--danger); }
    .tg-tag.warn { background: rgba(245,158,11,0.08); color: var(--warning); border-color: rgba(245,158,11,0.15); }
    .tg-main { display: flex; flex-direction: column; gap: 16px; }
    .tg-actions { display: flex; flex-wrap: wrap; gap: 10px; }
    .tg-actions .tg-btn { flex: 1; min-width: 120px; }
    .tg-btn { padding: 12px 16px; border-radius: 10px; border: none; cursor: pointer; font-weight: 600; font-size: 13px; transition: all 0.2s ease; display: flex; align-items: center; justify-content: center; gap: 6px; color: white; }
    .tg-btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
    .tg-btn-blue { background: linear-gradient(135deg, #0088cc, #00a8e6); }
    .tg-btn-green { background: linear-gradient(135deg, #22c55e, #059669); }
    .tg-btn-purple { background: linear-gradient(135deg, #14b8a6, #10b981); }
    .tg-btn-orange { background: linear-gradient(135deg, #f59e0b, #d97706); }
    .tg-webhook { display: flex; gap: 8px; align-items: center; margin-top: 10px; }
    .tg-webhook-input { flex: 1; padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border-solid); background: var(--card-solid); font-size: 12px; font-family: monospace; color: var(--text-sec); }
    .tg-webhook-btn { padding: 8px 14px; background: linear-gradient(135deg, var(--primary), var(--primary-end)); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 600; white-space: nowrap; }
    .tg-status { margin-top: 10px; padding: 8px 12px; border-radius: 8px; font-size: 12px; display: flex; align-items: center; gap: 6px; }
    .tg-status.success { background: rgba(34,197,94,0.06); color: var(--success); }
    .tg-status.error { background: rgba(239,68,68,0.06); color: var(--danger); }
    .tg-commands-title { font-size: 13px; font-weight: 700; margin-bottom: 10px; color: var(--text); }
    .tg-commands { display: flex; flex-wrap: wrap; gap: 8px; }
    .tg-commands .tg-cmd { flex: 1; min-width: 100px; padding: 10px; border-radius: 8px; background: rgba(120,120,120,0.03); border: 1px solid var(--border); transition: all 0.2s ease; }
    .tg-cmd:hover { border-color: rgba(0,136,204,0.2); background: rgba(0,136,204,0.03); }
    .tg-cmd-name { font-family: monospace; font-size: 12px; font-weight: 700; color: #0088cc; margin-bottom: 2px; }
    .tg-cmd-desc { font-size: 11px; color: var(--text-sec); }
    .tg-divider { height: 1px; background: var(--border); }

    /* 设置分组折叠 */
    .settings-group { background: var(--card); border: 1px solid var(--border); border-radius: 16px; margin-bottom: 16px; overflow: hidden; }
    .settings-group > summary { list-style: none; cursor: pointer; display: flex; align-items: center; gap: 12px; padding: 16px 22px; user-select: none; transition: background 0.2s; }
    .settings-group > summary::-webkit-details-marker { display: none; }
    .settings-group > summary .sg-icon { width: 38px; height: 38px; border-radius: 10px; background: linear-gradient(135deg, var(--primary), var(--primary-end)); display: flex; align-items: center; justify-content: center; font-size: 20px; flex-shrink: 0; }
    .settings-group > summary .sg-title { font-size: 17px; font-weight: 700; }
    .settings-group > summary .sg-sub { font-size: 12px; color: var(--text-sec); font-weight: 400; }
    .settings-group > summary .sg-chev { margin-left: auto; font-size: 14px; color: var(--text-sec); transition: transform 0.25s ease; }
    .settings-group[open] > summary .sg-chev { transform: rotate(180deg); }
    .settings-group > summary:hover { background: rgba(120,120,120,0.04); }
    .settings-body { padding: 4px 16px 16px; display: flex; flex-direction: column; gap: 0; }
    .settings-body .card { margin-bottom: 14px; box-shadow: none; }
    .settings-body .card:last-child { margin-bottom: 0; }

    @media (max-width: 768px) {
        :root { --nav-height: 56px; }
        .container { padding: 0 10px; padding-top: calc(var(--nav-height) + 10px); }
        .top-nav { padding: 0 10px; height: var(--nav-height); }
        .nav-left { gap: 8px; }
        .nav-brand { font-size: 15px; }
        .nav-version { display: none; }
        .nav-trace { margin-left: 8px; padding-left: 8px; gap: 8px; font-size: 11px; }
        .nav-trace-item { gap: 3px; }
        .nav-trace-label { display: none; }
        .nav-trace-value { font-size: 11px; }
        .nav-right { gap: 6px; }
        .nav-rtt { padding: 5px 8px; font-size: 11px; }
        .nav-rtt-value { font-size: 11px; min-width: 40px; }
        .nav-btn { padding: 6px 10px; font-size: 12px; }
        .nav-theme-btn { width: 32px; height: 32px; font-size: 16px; }

        .card { padding: 14px; border-radius: 12px; margin-bottom: 10px; }
        .section-header { flex-direction: column; align-items: flex-start; gap: 10px; margin-bottom: 14px; }
        .section-title { font-size: 15px; }
        .toolbar { flex-direction: column; align-items: stretch; gap: 8px; margin-bottom: 12px; }
        .toolbar > * { width: 100%; }
        .toolbar .btn-submit, .toolbar .btn-outline { justify-content: center; }
        .search-input { width: 100%; }

        .stat-grid { grid-template-columns: repeat(2, 1fr); gap: 8px; }
        .stat-item { padding: 10px 8px; }
        .stat-label { font-size: 11px; }
        .stat-value { font-size: 14px; }

        .node-grid { grid-template-columns: 1fr; gap: 10px; }
        .emby-card { padding: 14px; gap: 10px; }
        .card-header { padding-bottom: 10px; }
        .emby-icon { width: 36px; height: 36px; font-size: 20px; }
        .info-row { flex-direction: column; gap: 4px; }
        .info-label { min-width: auto; }
        .card-footer { flex-direction: column; gap: 6px; }
        .card-footer .btn-edit, .card-footer .btn-del { width: 100%; text-align: center; justify-content: center; }
        .node-details summary { font-size: 12px; }

        .table-wrapper { border: none; background: transparent; overflow: visible; }
        table, thead, tbody, th, td, tr { display: block; width: 100%; }
        thead { display: none; }
        tr { margin-bottom: 10px; background: var(--card-solid); border-radius: 12px; border: 1px solid var(--border); box-shadow: var(--shadow-card); overflow: hidden; backdrop-filter: blur(20px); }
        body.dark tr { background: #1a1a1a; }
        td { display: flex; align-items: center; padding: 10px 12px; border-bottom: 1px solid var(--border); text-align: right; gap: 8px; min-height: 44px; font-size: 13px; }
        td:last-child { border-bottom: none; }
        td[colspan] { justify-content: center; text-align: center; }
        td[colspan]::before { display: none !important; }
        td::before { content: attr(data-label); font-weight: 600; color: var(--text-sec); flex-shrink: 0; margin-right: auto; text-align: left; font-size: 12px; }

        .action-group { width: 100%; justify-content: flex-end; }
        .icon-btn { width: 32px; height: 32px; font-size: 15px; }

        .modal-overlay { padding: 8px; }
        .modal-card { margin: 8px auto; border-radius: 12px; }
        .modal-header { padding: 14px 14px 0; }
        .modal-body { padding: 14px; }
        .modal-title { font-size: 15px; flex-direction: column; align-items: flex-start; gap: 4px; }
        .chart-row { flex-direction: column; gap: 10px; }
        .chart-col { min-width: 100%; padding: 12px; }
        .chart-col-main, .chart-col-side { min-width: 100%; }
        .dashboard-charts { grid-template-columns: 1fr; }

        .nav-btn span.btn-text { display: none; }
        .nav-rtt span.rtt-label { display: none; }
        .batch-bar { flex-direction: column; align-items: stretch; gap: 8px; }
        .batch-divider { width: 100%; height: 1px; }

        .tg-main { grid-template-columns: 1fr; }
        .tg-actions { flex-direction: column; }
        .tg-actions .tg-btn { min-width: 100%; }
        .tg-commands { flex-direction: column; }
        .tg-commands .tg-cmd { min-width: 100%; }
        .tg-divider { width: 100%; height: 1px; }

        .btn-submit, .btn-outline, .btn-danger { padding: 10px 14px; font-size: 13px; min-height: 40px; }
        .form-input { padding: 9px 12px; font-size: 14px; min-height: 40px; }
        select.form-input { min-height: 40px; }

        #toast { padding: 10px 16px; font-size: 13px; max-width: 95vw; }
        #toast.show { top: calc(var(--nav-height) + 8px); }

        .info-panel { padding: 10px 12px; font-size: 12px; }

        .url-list-item { font-size: 11px; }
        .dynamic-url { max-width: 150px; }
    }
`;

const LOGIN_UI = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>智能反代系统 · 后台授权</title>
    <style>
        ${CSS_COMMON}
        body { display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 16px; margin: 0; background: var(--bg); }
        .login-wrapper { width: 100%; max-width: 400px; }
        .login-card { background: var(--card); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px); padding: 40px 32px; border-radius: 20px; box-shadow: var(--shadow-card); border: 1px solid var(--border); text-align: center; }
        .login-logo { width: 56px; height: 56px; margin: 0 auto 20px; background: linear-gradient(135deg, var(--primary), var(--primary-end)); border-radius: 16px; display: flex; align-items: center; justify-content: center; font-size: 28px; box-shadow: 0 4px 16px rgba(16,185,129,0.3); }
        .login-title { font-size: 22px; font-weight: 700; margin-bottom: 6px; color: var(--text); }
        .login-subtitle { font-size: 13px; color: var(--text-sec); margin-bottom: 28px; }
        .login-input { width: 100%; padding: 14px 16px; margin-bottom: 16px; border: 1px solid var(--border-solid); border-radius: 12px; background: var(--card-solid); color: var(--text); font-size: 14px; transition: all 0.2s ease; }
        body.dark .login-input { background: #1a1a1a; border-color: #2a2a2a; }
        .login-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(16,185,129,0.12); }
        .login-input::placeholder { color: var(--text-sec); }
        .login-btn { width: 100%; padding: 14px; background: linear-gradient(135deg, var(--primary), var(--primary-end)); color: white; border: none; border-radius: 12px; cursor: pointer; font-weight: 600; font-size: 15px; transition: all 0.25s ease; box-shadow: 0 4px 12px rgba(16,185,129,0.3); }
        .login-btn:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(16,185,129,0.4); }
        .login-btn:active { transform: translateY(0); }
    </style>
</head>
<body>
    <div id="toast"></div>
    <div class="login-wrapper">
        <div class="login-card">
            <div class="login-logo">🔐</div>
            <div class="login-title">安全验证</div>
            <div class="login-subtitle">请输入密钥以访问管理面板</div>
            <input type="password" id="tokenInput" class="login-input" placeholder="请输入密钥 TOKEN" onkeydown="if(event.key==='Enter') login()">
            <button class="login-btn" onclick="login()">验证登录</button>
        </div>
    </div>
    <script>
        function showToast(msg) {
            const t = document.getElementById('toast');
            t.textContent = msg; t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 2000);
        }
        function login() {
            const token = document.getElementById('tokenInput').value.trim();
            if(!token) return showToast('请输入正确的密钥');
            document.cookie = 'admin_token=' + encodeURIComponent(token) + '; path=/; max-age=2592000;';
            window.location.href = '/admin';
        }
    </script>
</body>
</html>
`;

const LANDING_UI = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>智能反代系统 · 访问地址</title>
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#10b981">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<style>
:root{
  --bg:#0b1120; --card:#131c26; --border:#243140; --text:#e8eaed; --text-sec:#9aa3b2;
  --primary:#10b981; --primary-end:#14b8a6;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:radial-gradient(1200px 600px at 50% -10%,#0f3d2e,#0b1120);color:var(--text);min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:48px 16px}
.wrap{width:100%;max-width:640px}
.head{text-align:center;margin-bottom:36px}
.logo{width:64px;height:64px;border-radius:18px;margin:0 auto 16px;background:linear-gradient(135deg,var(--primary),var(--primary-end));display:flex;align-items:center;justify-content:center;font-size:30px;box-shadow:0 8px 24px rgba(16,185,129,.35)}
.head h1{font-size:24px;font-weight:700;margin-bottom:8px}
.head p{color:var(--text-sec);font-size:14px;line-height:1.6}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:18px 20px;display:flex;align-items:center;gap:16px;transition:.2s}
.cards .card:first-child{grid-column:1/-1}
.card.active{border-color:var(--primary);box-shadow:0 0 0 3px rgba(16,185,129,.18)}
.icon{width:46px;height:46px;border-radius:12px;display:flex;align-items:center;justify-content:center;flex-shrink:0;overflow:hidden}
.icon svg{width:28px;height:28px;display:block}
.icon.tri{background:rgba(16,185,129,.15);color:#6ee7b7;font-size:24px}
.icon.dx{background:#E60012}
.icon.lt{background:#E60012}
.icon.yd{background:#0085D0}
.info{flex:1;min-width:0}
.carrier{font-size:15px;font-weight:600;margin-bottom:3px}
.url{font-size:13px;color:var(--text-sec);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.acts{display:flex;gap:8px;flex-shrink:0}
.btn{border:1px solid var(--border);background:#1a2433;color:var(--text);padding:8px 14px;border-radius:10px;font-size:13px;cursor:pointer;text-decoration:none;transition:.15s;white-space:nowrap}
.btn:hover{border-color:var(--primary);color:#fff}
.btn.primary{background:linear-gradient(135deg,var(--primary),var(--primary-end));border:none;color:#fff}
.foot{margin-top:32px;text-align:center;font-size:13px;color:var(--text-sec)}
.foot a{color:var(--primary);text-decoration:none}
.tag{display:inline-block;font-size:11px;color:var(--text-sec);background:#1a2433;border:1px solid var(--border);padding:2px 8px;border-radius:999px;margin-left:8px}
.services{margin-top:28px}
.services > summary{font-size:15px;font-weight:600;color:var(--text-sec);display:flex;align-items:center;gap:8px;cursor:pointer;list-style:none;user-select:none;padding:6px 2px;margin-bottom:0}
.services > summary::-webkit-details-marker{display:none}
.services > summary::before{content:"";display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--primary)}
.services > summary::after{content:"▸";margin-left:auto;font-size:12px;transition:transform .2s;color:var(--text-sec)}
.services[open] > summary{margin-bottom:14px}
.services[open] > summary::after{transform:rotate(90deg)}
.svc-list{display:flex;flex-direction:column;gap:10px}
.svc{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:14px 16px;display:flex;align-items:center;gap:14px;transition:.15s}
.svc:hover{border-color:var(--primary)}
.svc-icon{width:40px;height:40px;border-radius:10px;background:rgba(16,185,129,.12);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;overflow:hidden}
.svc-icon img{width:100%;height:100%;object-fit:cover}
.svc-info{flex:1;min-width:0}
.svc-name{font-size:14px;font-weight:600;margin-bottom:2px}
.svc-prefix{font-size:13px;color:var(--text-sec)}
.svc-status{width:10px;height:10px;border-radius:50%;background:#9aa3b2;flex-shrink:0;margin-left:8px;animation:pulse 1.2s infinite}
.svc-status.online{background:#22c55e;animation:none;box-shadow:0 0 0 4px rgba(34,197,94,.15)}
.svc-status.offline{background:#ef4444;animation:none;box-shadow:0 0 0 4px rgba(239,68,68,.15)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
@media(max-width:560px){.cards{grid-template-columns:1fr}.cards .card:first-child{grid-column:auto}}
</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <div class="logo">🚀</div>
    <h1>智能反代系统 · 访问地址</h1>
    <p>请根据你的运营商选择对应入口；不确定就直接用「三网通用」。<br>复制地址发给朋友，或点「打开」立即使用。</p>
  </div>
  <div class="cards">
    <div class="card" data-host="fandai.erebus.de5.net">
      <div class="icon tri">🌐</div>
      <div class="info"><div class="carrier">三网通用</div><div class="url">https://fandai.erebus.de5.net</div></div>
      <div class="acts"><button class="btn copy" data-url="https://fandai.erebus.de5.net">复制</button><a class="btn primary" href="https://fandai.erebus.de5.net" target="_blank">打开</a></div>
    </div>
    <div class="card" data-host="dx.erebus.de5.net">
      <div class="icon dx"><svg viewBox="0 0 100 100" width="28" height="28" fill="none"><rect width="100" height="100" rx="20" fill="#E60012"/><path d="M50 18 L50 82 M28 32 L72 32 M28 68 L72 68" stroke="#fff" stroke-width="12" stroke-linecap="round"/><circle cx="50" cy="50" r="12" fill="#fff"/></svg></div>
      <div class="info"><div class="carrier">电信<span class="tag">DX</span></div><div class="url">https://dx.erebus.de5.net/</div></div>
      <div class="acts"><button class="btn copy" data-url="https://dx.erebus.de5.net/">复制</button><a class="btn primary" href="https://dx.erebus.de5.net/" target="_blank">打开</a></div>
    </div>
    <div class="card" data-host="lt.erebus.de5.net">
      <div class="icon lt"><svg viewBox="0 0 100 100" width="28" height="28"><rect width="100" height="100" rx="20" fill="#E60012"/><path d="M50 15 L85 50 L50 85 L15 50 Z M50 30 L70 50 L50 70 L30 50 Z" fill="none" stroke="#fff" stroke-width="8" stroke-linejoin="round"/></svg></div>
      <div class="info"><div class="carrier">联通<span class="tag">LT</span></div><div class="url">https://lt.erebus.de5.net/</div></div>
      <div class="acts"><button class="btn copy" data-url="https://lt.erebus.de5.net/">复制</button><a class="btn primary" href="https://lt.erebus.de5.net/" target="_blank">打开</a></div>
    </div>
    <div class="card" data-host="yd.erebus.de5.net">
      <div class="icon yd"><svg viewBox="0 0 100 100" width="28" height="28"><rect width="100" height="100" rx="20" fill="#0085D0"/><rect x="24" y="24" width="22" height="22" rx="4" fill="#fff"/><rect x="54" y="24" width="22" height="22" rx="4" fill="#fff" opacity=".45"/><rect x="39" y="54" width="22" height="22" rx="4" fill="#fff"/></svg></div>
      <div class="info"><div class="carrier">移动<span class="tag">YD</span></div><div class="url">https://yd.erebus.de5.net/</div></div>
      <div class="acts"><button class="btn copy" data-url="https://yd.erebus.de5.net/">复制</button><a class="btn primary" href="https://yd.erebus.de5.net/" target="_blank">打开</a></div>
    </div>
  </div>
  <!-- SERVICES -->
</div>
<script>
document.addEventListener('click', function(e){
  var b = e.target.closest('.copy');
  if(!b) return;
  var url = b.getAttribute('data-url');
  var orig = b.textContent;
  navigator.clipboard.writeText(url).then(function(){
    b.textContent='已复制'; setTimeout(function(){b.textContent=orig;},1500);
  }).catch(function(){ b.textContent='复制失败'; setTimeout(function(){b.textContent=orig;},1500); });
});
var cur = location.hostname;
document.querySelectorAll('.card').forEach(function(c){
  if(c.getAttribute('data-host') === cur) c.classList.add('active');
});
// 自动检测各媒体源站健康状态
fetch('/api/health').then(function(r){return r.json();}).then(function(data){
  if(!data || !data.checks) return;
  document.querySelectorAll('.svc-status').forEach(function(s){
    var prefix = s.getAttribute('data-prefix');
    var info = data.checks[prefix.replace('/','')] || data.checks[prefix];
    s.classList.remove('loading');
    if(info && info.online){
      s.classList.add('online');
      s.title = '源站在线' + (info.status ? ' (HTTP ' + info.status + ')' : '');
    }else{
      s.classList.add('offline');
      s.title = '源站异常' + (info && info.error ? '：' + info.error : '');
    }
  });
}).catch(function(e){
  document.querySelectorAll('.svc-status').forEach(function(s){
    s.classList.remove('loading'); s.classList.add('offline'); s.title = '检测失败';
  });
});
// 📱 PWA：注册 Service Worker（离线也能看地址）
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function(){
    navigator.serviceWorker.register('/sw.js').catch(function(){});
  });
}
</script>
</body>
</html>
`;

const HTML_UI = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>智能反代系统</title>
    <style>${CSS_COMMON}</style>
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@latest/Sortable.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap@1.6.0/dist/css/jsvectormap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.6.0/dist/jsvectormap.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.6.0/dist/maps/world.js"></script>
</head>
<body>
    <div id="toast"></div>

    <nav class="top-nav">
        <div class="nav-left">
            <span class="nav-brand">智能反代系统</span>
            <span class="nav-version">v1.2.3</span>
            <div class="nav-trace">
                <div class="nav-trace-item">
                    <span class="nav-trace-icon">📍</span>
                    <span class="nav-trace-label">访客入口</span>
                    <span id="trace-entry" class="nav-trace-value">雷达扫描中...</span>
                </div>
                <div class="nav-trace-item">
                    <span class="nav-trace-icon">🚀</span>
                    <span class="nav-trace-label">Worker 落地</span>
                    <span id="trace-egress" class="nav-trace-value success">雷达扫描中...</span>
                </div>
            </div>
        </div>
        <div class="nav-right">
            <div class="nav-rtt">
                <span class="nav-rtt-dot" id="rttDot"></span>
                <span class="rtt-label">RTT:</span>
                <span id="rttValue" class="nav-rtt-value">测算中</span>
            </div>
            <button class="nav-btn nav-theme-btn" id="themeToggle" onclick="toggleDarkMode()" title="切换深色模式">🌙</button>
            <button class="nav-btn nav-btn-primary" onclick="openDashboard()">📊 <span class="btn-text">数据大屏</span></button>
            <button class="nav-btn nav-btn-danger" onclick="logout()">退出</button>
        </div>
    </nav>

    <div id="dashboardModal" class="modal-overlay">
        <div class="modal-card">
            <button class="modal-close" onclick="closeDashboard()">✕</button>
            <div class="modal-header">
                <div class="modal-title">📊 数据大屏 <span class="modal-title-sub">精确访客画像分析</span></div>
                <div class="modal-traffic-bar">
                    <span>今天: <strong id="trafficToday">加载中...</strong></span>
                    <span>1周内: <strong id="traffic7d">加载中...</strong></span>
                    <span>1月内: <strong id="traffic30d">加载中...</strong></span>
                    <span>🔀 今日故障转移: <strong id="failoverToday" style="color:var(--warning);">加载中...</strong></span>
                </div>
            </div>
            <div class="modal-body">
                <div class="dashboard-charts">
                    <div class="dash-card">
                        <div class="dash-card-title">📈 全站播放趋势（7 天）</div>
                        <div class="dash-card-body" style="height:200px;"><canvas id="trendChart"></canvas></div>
                    </div>
                    <div class="dash-card">
                        <div class="dash-card-title">🧭 访客来源地占比</div>
                        <div class="dash-card-body" style="height:200px;"><canvas id="locationChart"></canvas></div>
                    </div>
                    <div class="dash-card">
                        <div class="dash-card-title">🌍 访问者地理分布</div>
                        <div class="dash-card-body" style="height:240px;"><div id="geoMap" style="border-radius:8px;"></div></div>
                    </div>
                    <div class="dash-card">
                        <div class="dash-card-title">📉 节点延迟趋势（7 天）</div>
                        <div class="dash-card-body" style="height:200px;"><canvas id="pingHistoryChart"></canvas></div>
                    </div>
                </div>
                <div class="modal-section-title">🕵️ 最新独立播放记录 <span class="modal-section-sub">(仅拦截 PlaybackInfo 真实播放)</span></div>
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>访问时间</th><th>目标节点</th><th>真实 IP 地址</th><th>归属地</th><th>客户端/设备标识</th></tr></thead>
                        <tbody id="logTableBody"><tr><td colspan="5" style="text-align:center; padding: 30px;">加载数据中...</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div class="container">
    <div id="updateAlert" class="card alert-card" style="display: none;">
            <div class="section-header" style="margin-bottom:0;">
                <div>
                    <div class="section-title" style="color: var(--success);">✨ 发现新版本！</div>
                    <p style="font-size: 13px; color: var(--text-sec); margin-top: 4px;" id="updateMsg">当前版本: v1.2.3 | 最新版本: v?.?.?</p>
                </div>
                <button class="btn-submit" onclick="doOnlineUpdate()" id="onlineUpdateBtn" style="background: linear-gradient(135deg, var(--success), #059669);">🚀 一键拉取并升级</button>
            </div>
        </div>
        <div class="content-wrap">
            

            <div class="card alert-card" style="border-left-color: var(--success);">
                <div class="section-header">
                    <div class="section-title" style="color: var(--success);">&#x1F916; 智能DNS自动调度</div>
                    <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                        <span id="autoDnsStatus" class="badge" style="background:rgba(34,197,94,0.1);color:var(--success);">运行中</span>
                        <span id="lastUpdateTime" style="font-size:12px;color:var(--text-sec);">加载中...</span>
                    </div>
                </div>

                <div style="background: rgba(34,197,94,0.04); padding: 16px; border-radius: 12px; border: 1px solid rgba(34,197,94,0.1); margin-bottom: 16px;">
                    <div class="stat-grid" style="margin-bottom:16px;">
                        <div class="stat-item">
                            <div class="stat-label">调度频率</div>
                            <div class="stat-value success">每6小时</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label">当前线路</div>
                            <div class="stat-value success" id="autoDnsIsp">移动专属</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label">推送节点</div>
                            <div class="stat-value success" id="autoDnsTopNDisplay">TOP 3</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label">评分维度</div>
                            <div class="stat-value success">延迟+稳定性</div>
                        </div>
                    </div>

                    <div style="background: rgba(16,185,129,0.04); padding: 12px; border-radius: 10px; border: 1px solid rgba(16,185,129,0.1); margin-bottom: 12px;">
                        <div style="font-size: 13px; color: var(--text-sec); margin-bottom: 10px; font-weight: 500;">&#x1F527; 调度策略配置</div>
                        <div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
                            <select id="autoDnsIspType" class="form-input" style="width: auto; min-width: 140px; font-size: 13px;">
                                <option value="移动">🟢 移动专属</option>
                                <option value="电信">🔵 电信专属</option>
                                <option value="联通">🟠 联通专属</option>
                                <option value="多线">🟣 多线BGP</option>
                                <option value="ipv6">🚀 IPv6节点</option>
                                <option value="优选">🌟 顶尖优选库</option>
                                <option value="all">🌐 综合混合源</option>
                            </select>
                            <select id="autoDnsTopN" class="form-input" style="width: auto; min-width: 80px; font-size: 13px;">
                                <option value="1">TOP 1</option>
                                <option value="2">TOP 2</option>
                                <option value="3" selected>TOP 3</option>
                                <option value="5">TOP 5</option>
                            </select>
                            <button class="btn-submit" onclick="saveAutoDnsConfig()" style="background: linear-gradient(135deg, #3b82f6, #10b981); font-size: 13px; padding: 6px 14px;">&#x1F4BE; 保存配置</button>
                        </div>
                        <div style="font-size: 12px; color: var(--text-sec); margin-top: 8px; line-height: 1.5;">
                            &#x1F4A1; 系统每6小时自动从预设源拉取节点、测速评分，将最优节点推送至DNS。支持移动/电信/联通/多线/IPv6/优选/混合等多种线路策略。
                        </div>
                    </div>

                    <div style="display:flex;gap:10px;flex-wrap:wrap;">
                        <button class="btn-submit" id="btnManualAutoDns" onclick="manualAutoUpdate()" style="background: linear-gradient(135deg, var(--success), #059669); flex: 1; min-width: 140px;">&#x1F680; 立即执行调度</button>
                        <button class="btn-submit" id="btnLoadHistory" onclick="loadDnsHistory()" style="background: linear-gradient(135deg, #14b8a6, #10b981); flex: 1; min-width: 140px;">&#x1F4CB; 查看执行记录</button>
                    </div>
                </div>

                <div style="background: rgba(16,185,129,0.04); padding: 16px; border-radius: 12px; border: 1px solid rgba(16,185,129,0.12); margin-bottom: 16px;">
                    <div class="section-title" style="color: var(--primary); margin-bottom: 8px;">&#x1F30D; 多线子域名调度 <span style="font-size:12px;color:var(--text-sec);font-weight:400;">（按运营商分流）</span></div>
                    <div style="font-size: 12px; color: var(--text-sec); margin-bottom: 12px; line-height: 1.5;">
                        💡 每个子域名独立跑一套运营商优选 IP 并推送到 DNS：<b>yd</b>=移动 / <b>lt</b>=联通 / <b>dx</b>=电信。客户端按自身网络选用对应子域名即可走该运营商最优线路。访问 <code style="background:rgba(120,120,120,.15);padding:2px 6px;border-radius:6px;">/go</code> 可自动识别网络并跳转。
                    </div>
                    <div id="subdomainList" style="display: flex; flex-direction: column; gap: 10px;"></div>
                    <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top: 12px;">
                        <button class="btn-submit" onclick="saveSubdomainConfig()" style="background: linear-gradient(135deg, #3b82f6, #10b981); flex: 1; min-width: 140px;">&#x1F4BE; 保存子域名配置</button>
                        <button class="btn-submit" onclick="manualSubdomainUpdate()" style="background: linear-gradient(135deg, var(--success), #059669); flex: 1; min-width: 140px;">&#x1F680; 立即调度全部</button>
                    </div>
                    <div id="subdomainResult" style="display:none; margin-top: 10px; padding: 10px 14px; border-radius: 10px; font-size: 13px; line-height: 1.6;"></div>
                </div>

                <div id="autoUpdateResult" style="display:none;margin-bottom:16px;padding:12px 16px;border-radius:10px;font-size:13px;line-height:1.6;"></div>

                <div id="dnsHistoryPanel" style="display:none;">
                    <div class="section-title" style="margin-bottom:12px;">&#x1F4DC; 调度执行记录</div>
                    <div id="dnsHistoryContent" style="max-height:400px;overflow-y:auto;">
                        <div style="text-align:center;color:var(--text-sec);padding:20px;">加载中...</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="section-header">
                    <div class="section-title">已反代的媒体库</div>
                    <div style="display: flex; gap: 8px; align-items:center; flex-wrap: wrap;">
                        <button class="btn-outline" onclick="pingAllNodes()">⚡ 全局测速</button>
                        <button class="btn-danger" id="btnPurge" onclick="purgeCache()">🧹 刷新全站海报</button>
                        <input type="text" id="searchNode" class="search-input" placeholder="🔍 搜索备注或后缀..." onkeyup="filterNodesList()">
                    </div>
                </div>
                <div class="batch-bar">
            <label style="cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px; font-size: 13px;">
                <input type="checkbox" id="selectAllNodes" onchange="toggleSelectAll(this)" class="ip-checkbox"> 
                全选节点
            </label>
            
            <div class="batch-divider"></div>
            <select id="batch-mode-select" class="form-input" style="padding: 7px 12px; font-weight: 600; font-size: 13px;">
                <option value="">🔄 读取模式中...</option>
            </select>

            <button class="btn-submit" onclick="batchUpdateModes()">
                🚀 批量应用模式
            </button>

            <span id="batch-status" style="font-size: 12px; font-weight: 600;"></span>
        </div>
                <div id="list-grid" class="node-grid">
                    <div style="text-align:center; color:var(--text-sec); grid-column: 1 / -1; padding: 40px;">读取数据中...</div>
                </div>
            </div>

            <div class="card">
                <div class="section-header">
                    <div class="section-title">部署 / 编辑反代节点</div>
                    <div style="display:flex; gap:8px;">
                        <button class="btn-outline" onclick="exportConfig()">📦 导出配置</button>
                        <button class="btn-outline" onclick="importConfig()">📥 导入配置</button>
                    </div>
                </div>
                
                <form id="addForm" style="display: flex; flex-direction: column; gap: 14px;">
                    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                        <input type="hidden" id="oldPrefix" value="">
                        <input type="text" id="remark" class="form-input" placeholder="节点备注 (如: Misaka服)" style="flex: 1;" required>
                        <input type="text" id="prefix" class="form-input" placeholder="短路径后缀 (如: misaka)" style="flex: 1;" required>
                        <select id="mode" class="form-input" style="flex: 1;">
                            <option value="off">保守 (抹除IP)</option>
                            <option value="realip_only">严格 (透传IP)</option>
                            <option value="dual">兼容 (双重透传)</option>
                            <option value="strict">强力 (防403)</option>
                        </select>
                    </div>

                    <div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
                        <div style="position: relative; flex: 2; display: flex;">
                            <div style="display:flex; gap:10px; align-items:center; background:var(--card-solid); padding:10px 14px; border-radius:10px; border:1px solid var(--border-solid); flex: 1; cursor: pointer; transition:0.2s;" onclick="toggleIconPicker(event)" id="iconSelectBtn">
                                <img id="iconPreview" src="" style="width:24px;height:24px;display:none;border-radius:4px;object-fit:cover;">
                                <span id="iconDefault" style="font-size:20px;line-height:1;">🎬</span>
                                <span id="iconSelectText" style="flex:1; color: var(--text-sec); font-size:13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">点击选择图标 (默认 🎬)</span>
                                <input type="hidden" id="iconUrl" value="">
                            </div>
                            
                            <div id="iconPickerPanel" style="display:none; position: absolute; top: 100%; left: 0; width: 100%; background: var(--card-solid); border: 1px solid var(--border-solid); border-radius: 12px; padding: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.15); z-index: 100; margin-top: 8px; flex-direction: column; gap: 10px;">
                                <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px;">
                                    <input type="text" id="customIconUrlInput" class="form-input" placeholder="输入自定义 JSON 图标库链接..." style="flex: 1; font-size: 12px;">
                                    <button type="button" class="btn-submit" onclick="setCustomIconLibrary()" style="padding: 7px 12px; font-size: 12px;">加载</button>
                                    <button type="button" class="btn-outline" onclick="resetIconLibrary()" style="padding: 7px 12px; font-size: 12px;">默认库</button>
                                </div>
                                <input type="text" id="iconSearch" class="form-input" placeholder="🔍 搜索图标名称..." style="width: 100%;" onkeyup="filterIcons()">
                                <div id="iconGrid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(44px, 1fr)); gap: 8px; overflow-y: auto; max-height: 240px; padding-right: 4px;">
                                    <div style="text-align:center; color:var(--text-sec); grid-column: 1 / -1; font-size: 13px;">加载图标库中...</div>
                                </div>
                            </div>
                        </div>
                        <label style="display:flex; align-items:center; gap:6px; font-size:13px; font-weight:500; cursor:pointer;">
                            <input type="checkbox" id="nodeCache" class="ip-checkbox" checked>
                            开启海报缓存
                        </label>
                        <button type="submit" id="submitBtn" class="btn-submit" style="flex: 1; padding: 12px 20px;">保存部署</button>
                    </div>

                    <div class="info-panel">
                        <div class="info-panel-label">服务器线路配置 (支持魔改分离版推流，支持无限条备用线路)</div>
                        <div id="targetInputs" style="display: flex; flex-direction: column; gap: 8px;">
                            <input type="url" class="target-input form-input" placeholder="主线路地址 (如: http://1.1.1.1:8096)" required oninput="handleTargetInputs()">
                            <input type="url" class="target-input form-input" placeholder="备用线路 1 (选填，主源挂掉时触发)" oninput="handleTargetInputs()">
                        </div>
                    </div>
                </form>
            </div>

        
<details class="settings-group">
            <summary>
                <span class="sg-icon">⚙️</span>
                <span class="sg-title">系统设置</span>
                <span class="sg-sub">（专属线路测速 / 调度模式 / Telegram / 核心层更新）</span>
                <span class="sg-chev">▾</span>
            </summary>
            <div class="settings-body">
            <div class="card">
                <div class="section-header">
                    <div class="section-title">⚡ 专属线路测速与动态 DNS 解析</div>
                </div>
                
                <div class="info-panel" style="margin-bottom: 16px;">
                    <div class="info-panel-label">📡 当前域名生效的 DNS 解析：</div>
                    <div id="dnsStatus" style="display: flex; gap: 8px; flex-wrap: wrap;">
                        <span style="color:var(--text-sec); font-size: 13px;">加载中...</span>
                    </div>
                </div>

                <div class="toolbar">
                    <select id="ipType" class="form-input" style="font-weight: 600; color: var(--primary);">
                        <option value="移动" selected>🟢 移动专属</option>
                        <option value="all">🌐 综合混合源</option>
                        <option value="电信">🔵 电信专属</option>
                        <option value="联通">🟠 联通专属</option>
                        <option value="多线">🟣 多线BGP</option>
                        <option value="ipv6">🚀 IPv6节点</option>
                        <option value="优选">🌟 顶尖优选库</option>
                    </select>

                    <button class="btn-submit" id="btnFetchRemote" onclick="fetchRemoteAndTest()">🌍 提取预设源并测速</button>
                    <button class="btn-outline" onclick="batchTcpPing()">🌐 复制去 ITDog</button>
                    <button class="btn-outline" onclick="clearTest()">🗑️ 清空列表</button>
                </div>

                <div class="info-panel" style="margin-bottom: 16px;">
                    <div style="display: flex; gap: 8px; margin-bottom: 12px; align-items: center; flex-wrap: wrap;">
                        <input type="text" id="customApiUrl" class="form-input" value="https://ip.v2too.top/api/nodes" placeholder="填入自定义 JSON 或 文本 API 链接" style="flex: 1; min-width: 200px;">
                        <button class="btn-submit" id="btnFetchCustomApi" onclick="fetchCustomApiAndTest()" style="background: linear-gradient(135deg, #3b82f6, #10b981);">🌐 拉取 API 并测速</button>
                    </div>

                    <textarea id="customIps" rows="2" class="form-input" placeholder="在此粘贴自定义 IPv4、IPv6 或 优选域名 (支持混杂文本，自动提取)" style="width: 100%; margin-bottom: 12px; font-family: 'SF Mono', monospace; resize: vertical;"></textarea>
                    
                    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                        <button class="btn-submit" id="btnTestCustom" onclick="testCustomIPs()" style="background: linear-gradient(135deg, #14b8a6, #10b981);">🧪 测试粘贴的节点</button>
                        <button class="btn-submit" id="btnDirectCname" onclick="directSubmitCname()" style="background: linear-gradient(135deg, #a855f7, #7c3aed);">🔗 直推 CNAME (免测速)</button>
                        <button class="btn-danger" id="btnTop3Dns" onclick="updateTop3ToDns()">🌟 更新 TOP3 至 DNS</button>
                        <button class="btn-submit" id="btnSelectedDns" onclick="updateSelectedToDns()" style="background: linear-gradient(135deg, var(--success), #059669);">☑️ 提交选中节点至 DNS</button>
                    </div>
                </div>
                
                <div id="statusText" class="status-msg" style="margin-bottom: 16px;">
                    💡 测速完成后，可勾选复选框自由组合，点击【提交选中节点至 DNS】自动分发。
                </div>

                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 40px; text-align: center;"><input type="checkbox" id="selectAll" class="ip-checkbox" onclick="toggleSelectAll()"></th>
                                <th>专属节点 (点击复制)</th>
                                <th>预估延迟</th>
                                <th>连通状态</th>
                                <th>记录类型/归属地</th>
                                <th>单节点操作</th>
                            </tr>
                        </thead>
                        <tbody id="testTableBody">
                            <tr><td colspan="6" style="text-align:center;color:var(--text-sec);">暂无数据，请拉取节点或输入自定义 IP/域名 测试</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
    <div class="card">
            <div class="section-header">
                <div class="section-title">⚙️ Worker 调度模式与区域设置</div>
            </div>
            <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                
                <select id="cf-mode-select" class="form-input" onchange="handleModeChange()" style="flex: 1; min-width: 180px;">
                    <option value='{"mode":"smart"}'>🤖 智能调度 (Smart Placement)</option>
                    <option value='{"mode":"off"}'>🌍 边缘节点 (Edge - 默认离访客近)</option>
                    <optgroup label="📍 指定云厂商物理机房落地">
                        <option value="aws">☁️ AWS (亚马逊云)</option>
                        <option value="gcp">☁️ GCP (谷歌云)</option>
                        <option value="azure">☁️ Azure (微软云)</option>
                    </optgroup>
                    <option value="custom">✏️ 手动输入区域代码...</option>
                </select>

                <select id="cf-region-select" class="form-input" style="display: none; flex: 1.5; min-width: 200px;">
                </select>

                <input type="text" id="cf-custom-input" class="form-input" placeholder="输入云代码 (如 gcp:us-west1)" style="display: none; flex: 1.5; min-width: 200px;">
                
                <button class="btn-submit" onclick="updatePlacement()">
                    提交修改
                </button>
            </div>
            <div id="place-status" style="margin-top: 10px; font-size: 13px; color: var(--text-sec); font-weight: 600;">后台全自动安全调度，不暴露任何私钥</div>
        </div>
        <div class="card tg-console">
            <div class="tg-console-header">
                <div class="tg-console-icon">✈️</div>
                <div class="tg-console-title">Telegram 机器人控制台</div>
            </div>
            <div class="tg-console-desc">这里不动核心代理逻辑，只增强 TG 相关体验。你可以直接从面板把完整统计、今日简报、节点热度榜、客户端分布发到默认 TG_CHAT_ID，也能一键复制 Webhook 地址。</div>
            <div class="tg-tags">
                <span class="tg-tag">🤖 依赖 TG_BOT_TOKEN</span>
                <span class="tg-tag success">📩 默认发送到 TG_CHAT_ID</span>
                <span class="tg-tag warn">📡 支持 /stats /today /top /clients /test</span>
            </div>
            
            <div class="tg-toggle">
                <span class="tg-toggle-label">🔔 Bot 推送消息</span>
                <label class="tg-toggle-switch">
                    <input type="checkbox" id="botToggle" checked onchange="toggleBotNotification()">
                    <span class="tg-toggle-slider"></span>
                </label>
                <span id="botToggleStatus" class="tg-toggle-status on">已开启</span>
            </div>
            
            <div class="tg-main">
                <div>
                    <div style="font-size: 13px; font-weight: 700; margin-bottom: 10px; color: var(--text);">一键操作</div>
                    <div class="tg-actions">
                        <button class="tg-btn tg-btn-blue" onclick="sendTgMessage('stats')">📊 完整播报</button>
                        <button class="tg-btn tg-btn-green" onclick="sendTgMessage('today')">📋 今日简报</button>
                        <button class="tg-btn tg-btn-purple" onclick="sendTgMessage('top')">🏆 节点 TOP</button>
                        <button class="tg-btn tg-btn-orange" onclick="sendTgMessage('clients')">👥 客户端分布</button>
                    </div>
                    <div class="tg-webhook">
                        <input type="text" id="tgWebhookUrl" class="tg-webhook-input" value="" readonly placeholder="Webhook 地址将显示在这里">
                        <button class="tg-webhook-btn" onclick="copyTgWebhook()">📋 复制 Webhook</button>
                    </div>
                    <div id="tgStatus" class="tg-status" style="display: none;"></div>
                </div>
                <div class="tg-divider"></div>
                <div>
                    <div class="tg-commands-title">Bot 命令速查</div>
                    <div class="tg-commands">
                        <div class="tg-cmd">
                            <div class="tg-cmd-name">/stats</div>
                            <div class="tg-cmd-desc">完整监控看板</div>
                        </div>
                        <div class="tg-cmd">
                            <div class="tg-cmd-name">/today</div>
                            <div class="tg-cmd-desc">今日访问简报</div>
                        </div>
                        <div class="tg-cmd">
                            <div class="tg-cmd-name">/top</div>
                            <div class="tg-cmd-desc">节点热度排名</div>
                        </div>
                        <div class="tg-cmd">
                            <div class="tg-cmd-name">/clients</div>
                            <div class="tg-cmd-desc">客户端分布</div>
                        </div>
                        <div class="tg-cmd">
                            <div class="tg-cmd-name">/test</div>
                            <div class="tg-cmd-desc">Bot 在线自检</div>
                        </div>
                        <div class="tg-cmd">
                            <div class="tg-cmd-name">/help</div>
                            <div class="tg-cmd-desc">命令帮助菜单</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
            <div class="card alert-card danger">
    <div class="section-header" style="margin-bottom:12px;">
        <div class="section-title" style="color: var(--danger);">🚀 一键覆盖/更新 Worker 核心层代码</div>
    </div>
    <div style="font-size: 13px; color: var(--text-sec); margin-bottom: 12px;">⚠️ 警告：提交错误的代码会导致面板瞬间崩溃（500 错误）。请确保代码已在本地测试通过！</div>
    <textarea id="codeArea" rows="6" class="form-input" placeholder="方式一：在此处直接粘贴修改好的最新代码全文..." style="width: 100%; margin-bottom: 12px; font-family: 'SF Mono', monospace; resize: vertical; font-size:12px;"></textarea>
    <div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
        <span style="font-size:13px; font-weight:600;">或 方式二：</span>
        <input type="file" id="fileInput" accept=".js" class="form-input" style="font-size:13px; padding: 6px;">
        <button class="btn-danger" id="deployBtn" onclick="deployWorker()" style="margin-left: auto;">🔥 立即覆盖部署并重启节点</button>
    </div>
</div>
            <div class="card">
                <div class="section-header">
                    <div class="section-title">🌟 Cloudflare 优选域名测速</div>
                    <button class="btn-submit" onclick="runDomainSpeedTest()" style="background: linear-gradient(135deg, var(--primary), var(--primary-end));">🚀 开始测速</button>
                </div>
                <div style="font-size:12px;color:var(--text-sec);margin-bottom:12px;">边缘节点对各优选域名发 HEAD /cdn-cgi/trace 测速，按客户端网段缓存 1 小时。复制最快域名可作反代目标前缀，从最快 Cloudflare 边缘回源。</div>
                <div id="domainSpeedResult" style="display:flex;flex-direction:column;gap:8px;">点击「开始测速」获取各优选域名延迟…</div>
            </div>
            <div class="card">
                <div class="section-header">
                    <div class="section-title">🔀 运行时故障转移</div>
                    <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;">
                        <input type="checkbox" id="failoverToggle" onchange="toggleFailover()" style="width:18px;height:18px;accent-color:var(--primary);">
                        <span id="failoverToggleStatus" style="color:var(--text-sec);">加载中...</span>
                    </label>
                </div>
                <div style="font-size:12px;color:var(--text-sec);">某节点请求失败（5xx / 连接错误 / 超时）时，本次请求自动重试同路由的备用节点；近期判定不可用的节点在 60 秒内被直接跳过，实现秒级切换。故障转移次数可在「数据大屏」查看。</div>
            </div>
            </div>
        </details>
</div>
        
        <div class="footer">
            <div class="footer-text">
                <strong>免责声明:</strong> 本项目仅供学习与技术测试使用，请遵守当地法律法规。使用者对配置、转发内容与访问行为承担全部责任，开发者不对任何直接或间接损失负责。
            </div>
        </div>
    </div>

    <script>
        const CURRENT_VERSION = '1.2.3';
        const GITHUB_RAW_URL = 'https://raw.githubusercontent.com/PzErebus/fandai/main/worker.js';
        const CF_DOMAIN = 'fandai.erebus.de5.net';
        
        const modeNames = { 'off': '保守', 'realip_only': '严格', 'dual': '兼容', 'strict': '强力' };
        
        const DEFAULT_ICON_URL = 'https://raw.githubusercontent.com/baiitang/Sakura/main/Fileball/Yuan/tubiao.json';
        let globalIcons = [];
        let proxyNodesForPing = [];
        let sortableInstance = null;
        let trendChartInstance = null;
        let locationChartInstance = null;

        // ==========================================
        // 前端安全工具函数 (Frontend Security Utilities)
        // ==========================================
        function escapeHtml(text) {
            if (text === null || text === undefined) return '';
            const str = String(text);
            return str
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function isValidUrl(urlStr) {
            try {
                if (!urlStr) return false;
                const url = new URL(urlStr);
                return url.protocol === 'http:' || url.protocol === 'https:';
            } catch(e) {
                return false;
            }
        }

        function safeJsonParse(str, fallback = null) {
            try {
                return JSON.parse(str);
            } catch(e) {
                console.warn('JSON parse failed:', e.message);
                return fallback;
            }
        }

        // 设置 Chart.js 响应暗色模式
        function updateChartColors() {
            Chart.defaults.color = document.body.classList.contains('dark') ? '#98989d' : '#86868b';
            Chart.defaults.borderColor = document.body.classList.contains('dark') ? '#38383a' : '#d2d2d7';
        }

        // ==========================================
        // Bot推送开关功能
        // ==========================================
        async function loadBotConfig() {
            try {
                const res = await fetch('/api/bot-config');
                const data = await res.json();
                if (data.success) {
                    const toggle = document.getElementById('botToggle');
                    const status = document.getElementById('botToggleStatus');
                    if (toggle && status) {
                        toggle.checked = data.enabled;
                        status.textContent = data.enabled ? '已开启' : '已关闭';
                        status.className = 'tg-toggle-status ' + (data.enabled ? 'on' : 'off');
                    }
                }
            } catch(e) {
                console.warn('加载Bot配置失败:', e);
            }
        }

        // ==========================================
        // 🔀 运行时故障转移开关
        // ==========================================
        async function loadFailoverConfig() {
            try {
                const res = await fetch('/api/get-cfg?key=failover_enabled');
                const data = await res.json();
                const toggle = document.getElementById('failoverToggle');
                const status = document.getElementById('failoverToggleStatus');
                if (toggle && status && data.success) {
                    const on = data.value !== 'off';
                    toggle.checked = on;
                    status.textContent = on ? '已开启' : '已关闭';
                    status.style.color = on ? 'var(--success)' : 'var(--danger)';
                }
            } catch(e) { console.warn('加载故障转移配置失败:', e); }
        }

        async function toggleFailover() {
            const toggle = document.getElementById('failoverToggle');
            const status = document.getElementById('failoverToggleStatus');
            if (!toggle || !status) return;
            const enabled = toggle.checked;
            try {
                const res = await fetch('/api/set-cfg', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key: 'failover_enabled', value: enabled ? 'on' : 'off' })
                });
                const data = await res.json();
                if (data.success) {
                    status.textContent = enabled ? '已开启' : '已关闭';
                    status.style.color = enabled ? 'var(--success)' : 'var(--danger)';
                    showToast(enabled ? '🔀 运行时故障转移已开启' : '⏸ 运行时故障转移已关闭');
                } else {
                    toggle.checked = !enabled;
                    showToast('❌ ' + (data.error || '设置失败'));
                }
            } catch(e) { toggle.checked = !enabled; showToast('❌ 网络错误'); }
        }

        async function toggleBotNotification() {
            const toggle = document.getElementById('botToggle');
            const status = document.getElementById('botToggleStatus');
            if (!toggle || !status) return;
            
            const enabled = toggle.checked;
            try {
                const res = await fetch('/api/bot-config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: enabled })
                });
                const data = await res.json();
                if (data.success) {
                    status.textContent = enabled ? '已开启' : '已关闭';
                    status.className = 'tg-toggle-status ' + (enabled ? 'on' : 'off');
                    showToast(enabled ? '🔔 Bot推送已开启' : '🔕 Bot推送已关闭');
                } else {
                    // 恢复原状态
                    toggle.checked = !enabled;
                    showToast('❌ ' + (data.error || '设置失败'));
                }
            } catch(e) {
                // 恢复原状态
                toggle.checked = !enabled;
                showToast('❌ 网络错误');
            }
        }

        // =====================================
        // Telegram 机器人控制台功能
        // =====================================
        function initTgConsole() {
            const webhookInput = document.getElementById('tgWebhookUrl');
            if (webhookInput) {
                webhookInput.value = window.location.origin + '/api/webhook';
            }
        }

        async function sendTgMessage(type) {
            const statusDiv = document.getElementById('tgStatus');
            statusDiv.style.display = 'flex';
            statusDiv.className = 'tg-status';
            statusDiv.innerHTML = '⏳ 正在发送 ' + type + ' 消息到 Telegram...';

            try {
                const res = await fetch('/api/send-tg-message', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: type })
                });
                const data = await res.json();

                if (data.success) {
                    statusDiv.className = 'tg-status success';
                    statusDiv.innerHTML = '✅ 已发送到默认 Telegram 聊天 (动作: ' + type + ')';
                } else {
                    statusDiv.className = 'tg-status error';
                    statusDiv.innerHTML = '❌ 发送失败: ' + (data.error || '未知错误');
                }
            } catch (e) {
                statusDiv.className = 'tg-status error';
                statusDiv.innerHTML = '❌ 网络异常: ' + e.message;
            }

            setTimeout(() => { statusDiv.style.display = 'none'; }, 5000);
        }

        function copyTgWebhook() {
            const input = document.getElementById('tgWebhookUrl');
            if (input && input.value) {
                navigator.clipboard.writeText(input.value).then(() => {
                    showToast('📋 Webhook 地址已复制到剪贴板');
                });
            }
        }

        // =====================================
        // 数据大屏与统计逻辑 (适配手机端表格排版)
        // =====================================
        async function openDashboard() {
            document.getElementById('dashboardModal').style.display = 'block';
            
            function parseTrafficToBytes(str) {
                if (!str || str === '0 B' || str.includes('异常') || str.includes('获取')) return 0;
                let val = parseFloat(str);
                if (str.includes('TB')) return val * 1099511627776;
                if (str.includes('GB')) return val * 1073741824;
                if (str.includes('MB')) return val * 1048576;
                if (str.includes('KB')) return val * 1024;
                return val;
            }

            let top5Container = document.getElementById('top5-simple-container');
            if (!top5Container) {
                top5Container = document.createElement('div');
                top5Container.id = 'top5-simple-container';
                const wrapper = document.querySelector('.table-wrapper');
                if(wrapper && wrapper.previousElementSibling) {
                    wrapper.parentNode.insertBefore(top5Container, wrapper.previousElementSibling);
                }
            }
            
            let top5Html = '<h3 style="margin-top: 30px; margin-bottom:16px;">🏆 今日节点热度 TOP 5</h3><div style="background: rgba(120,120,120,0.05); padding: 16px; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 20px;">';
            
            // ==========================================
            // 🚀 从 /api/routes 接口获取各节点今日请求数
            // ==========================================
            try {
                const routesRes = await fetch('/api/routes');
                const routesData = await routesRes.json();
                
                if (Array.isArray(routesData) && routesData.length > 0) {
                    // 过滤出有今日请求数的节点并排序
                    const validNodes = routesData.filter(r => (r.todayReqs || 0) > 0);
                    const top5 = validNodes.sort((a, b) => (b.todayReqs || 0) - (a.todayReqs || 0)).slice(0, 5);
                    
                    if (top5.length > 0) {
                        top5Html += '<ul style="margin:0; padding-left: 20px; line-height: 2; font-size: 14px; color: var(--text);">';
                        top5.forEach((r, idx) => {
                            const rankColor = idx === 0 ? 'var(--danger)' : (idx === 1 ? 'var(--warning)' : '#eab308');
                            const remark = r.remark || r.prefix;
                            top5Html += '<li><strong style="color:' + rankColor + '; font-size: 15px;">#' + (idx+1) + '</strong> ' + remark + ' (/' + r.prefix + ') —— 今日播放: <strong style="color:var(--primary); font-family: monospace;">' + r.todayReqs + ' 次</strong></li>';
                        });
                        top5Html += '</ul>';
                    } else {
                        top5Html += '<div style="color:var(--text-sec); font-size:13px; text-align:center;">今日暂无节点产生播放</div>';
                    }
                } else {
                    top5Html += '<div style="color:var(--text-sec); font-size:13px; text-align:center;">暂无节点数据</div>';
                }
            } catch (e) {
                top5Html += '<div style="color:var(--text-sec); font-size:13px; text-align:center;">数据加载失败</div>';
            }
            top5Html += '</div>';
            
            top5Container.innerHTML = top5Html;


            // ==========================================
            // 🌟 正常加载下面的图表数据 (带有10秒防卡死超时保护)
            // ==========================================
            document.getElementById('logTableBody').innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 30px;">数据分析引擎计算中...</td></tr>';
            document.getElementById('trafficToday').innerText = '拉取中...';
            document.getElementById('traffic7d').innerText = '拉取中...';
            document.getElementById('traffic30d').innerText = '拉取中...';

            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10000);

                const res = await fetch('/api/analytics', { signal: controller.signal });
                clearTimeout(timeoutId);
                
                const data = await res.json();
                if(!data.success) throw new Error(data.error);

                updateChartColors();

                document.getElementById('trafficToday').innerText = data.trafficToday || '未知';
                document.getElementById('traffic7d').innerText = data.traffic7d || '未知';
                document.getElementById('traffic30d').innerText = data.traffic30d || '未知';

                const labels = data.trend.map(i => i.date.substring(5)); 
                const counts = data.trend.map(i => i.count);
                const trendCtx = document.getElementById('trendChart').getContext('2d');
                if(trendChartInstance) trendChartInstance.destroy();
                trendChartInstance = new Chart(trendCtx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{ label: '有效播放 (次)', data: counts, borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.1)', fill: true, tension: 0.3, pointRadius: 2 }]
                    },
                    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { font: {size: 10} } }, y: { ticks: { font: {size: 10} }, beginAtZero: true } } }
                });

                const locLabels = data.locations.map(i => i.country === 'CN' ? '中国大陆' : (i.country || '未知'));
                const locCounts = data.locations.map(i => i.count);
                const locCtx = document.getElementById('locationChart').getContext('2d');
                if(locationChartInstance) locationChartInstance.destroy();
                locationChartInstance = new Chart(locCtx, {
                    type: 'doughnut',
                    data: {
                        labels: locLabels,
                        datasets: [{ data: locCounts, backgroundColor: ['#22c55e', '#10b981', '#f59e0b', '#a855f7', '#ef4444', '#6b7280'], borderWidth: 0 }]
                    },
                    options: { responsive: true, maintainAspectRatio: false, cutout: '60%', plugins: { legend: { position: 'right', labels: { boxWidth: 10, font: {size: 10}, padding: 6 } } } }
                });

                // 🔀 今日故障转移统计
                const foEl = document.getElementById('failoverToday');
                if (foEl) foEl.innerText = (data.failoverToday || 0) + ' 次';

                // 🌍 访问者地理分布世界地图
                const mapEl = document.getElementById('geoMap');
                if (mapEl && typeof jsVectorMap !== 'undefined') {
                    const regionValues = {};
                    (data.locations || []).forEach(l => { if (l.country) regionValues[l.country] = Number(l.count) || 0; });
                    try {
                        if (window.__geoMap) { window.__geoMap.destroy(); window.__geoMap = null; }
                        window.__geoMap = new jsVectorMap({
                            selector: '#geoMap',
                            map: 'world',
                            backgroundColor: 'transparent',
                            zoomButtons: true,
                            regionStyle: { initial: { fill: '#2a3140' }, hover: { fill: '#10b981', fillOpacity: 0.6 } },
                            series: { regions: [{ values: regionValues, scale: ['#1e3a8a', '#10b981', '#a855f7'], normalizeFunction: 'polynomial' }] },
                            onRegionTooltipShow: (event, tooltip, code) => { tooltip.text(code + '：' + (regionValues[code] || 0) + ' 次播放', true); }
                        });
                    } catch (e) { mapEl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-sec);font-size:13px;">地图加载失败</div>'; }
                }

                // 📉 节点延迟趋势（近 7 天）
                try {
                    const phRes = await fetch('/api/ping-history');
                    const phData = await phRes.json();
                    const phCanvas = document.getElementById('pingHistoryChart');
                    if (phData.success && phData.points && phData.points.length && phCanvas) {
                        const byPrefix = {};
                        phData.points.forEach(p => { if (!byPrefix[p.prefix]) byPrefix[p.prefix] = {}; byPrefix[p.prefix][p.day] = p.avg_ms; });
                        const days = [...new Set(phData.points.map(p => p.day))].sort();
                        const palettes = ['#10b981', '#22c55e', '#f59e0b', '#ef4444', '#a855f7', '#06b6d4', '#ec4899'];
                        const datasets = Object.keys(byPrefix).map((pfx, i) => ({ label: '/' + pfx, data: days.map(d => byPrefix[pfx][d] ?? null), borderColor: palettes[i % palettes.length], backgroundColor: 'transparent', tension: 0.3, spanGaps: true }));
                        const phCtx = phCanvas.getContext('2d');
                        if (window.__pingHistoryChart) window.__pingHistoryChart.destroy();
                        window.__pingHistoryChart = new Chart(phCtx, {
                            type: 'line',
                            data: { labels: days.map(d => d.substring(5)), datasets },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {
                                    title: { display: true, text: '各节点平均延迟 (ms)', font: {size: 13} },
                                    legend: { position: 'bottom', labels: { boxWidth: 10, font: {size: 11}, padding: 8 } }
                                },
                                scales: { y: { beginAtZero: true, ticks: { font: {size: 10} } }, x: { ticks: { font: {size: 10} } } }
                            }
                        });
                    } else if (phCanvas) {
                        phCanvas.parentNode.insertAdjacentHTML('beforeend', '<div style="font-size:12px;color:var(--text-sec);text-align:center;padding:20px;">暂无测速历史（在节点卡片点「测速」即可记录）</div>');
                    }
                } catch (e) {}

                const tbody = document.getElementById('logTableBody');
                tbody.innerHTML = '';
                if(data.recents.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 30px;">暂无日志记录</td></tr>';
                } else {
                    data.recents.forEach(log => {
                        const tr = document.createElement('tr');
                        const isChina = log.country === 'CN';
                        tr.innerHTML = \`
                            <td data-label="访问时间" style="font-size:12px; white-space:nowrap;">\${log.timestamp}</td>
                            <td data-label="目标节点"><span class="badge" style="background:rgba(16,185,129,0.08);color:var(--primary);">\${log.prefix}</span></td>
                            <td data-label="真实 IP" style="font-family:'SF Mono',monospace; font-size:12px; color:var(--text-sec); word-break:break-all;">\${log.ip}</td>
                            <td data-label="归属地"><span class="badge" style="background:\${isChina ? 'rgba(34,197,94,0.08)' : 'rgba(245,158,11,0.08)'}; color:\${isChina ? 'var(--success)' : 'var(--warning)'};">\${isChina ? '中国大陆' : (log.country || 'Unknown')}</span></td>
                            <td data-label="设备标识 (UA)" style="font-size:11px; color:var(--text-sec); word-break: break-all; white-space: normal; text-align: right; line-height: 1.4;" title="\${log.ua}">\${log.ua}</td>
                        \`;
                        tbody.appendChild(tr);
                    });
                }

            } catch (e) {
                const errMsg = e.name === 'AbortError' ? '网络超时，CF 接口拥堵，请稍后重试' : e.message;
                document.getElementById('logTableBody').innerHTML = \`<tr><td colspan="5" style="text-align:center;color:var(--danger); padding: 30px;">独立图表数据拉取失败: \${errMsg}</td></tr>\`;
            }
        }

        function closeDashboard() { document.getElementById('dashboardModal').style.display = 'none'; }

        async function loadIcons(forceUrl = null) {
            const grid = document.getElementById('iconGrid');
            if (!grid) return;
            grid.innerHTML = '<div style="grid-column: 1/-1; color: var(--text-sec); font-size: 13px; text-align: center;">加载图标库中...</div>';
            const targetUrl = forceUrl || localStorage.getItem('custom_icon_url') || DEFAULT_ICON_URL;
            const urlInput = document.getElementById('customIconUrlInput');
            if (urlInput) urlInput.value = targetUrl === DEFAULT_ICON_URL ? '' : targetUrl;
            
            // 添加超时控制，3秒超时
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            
            try {
                const res = await fetch(targetUrl, { signal: controller.signal });
                clearTimeout(timeoutId);
                const data = await res.json();
                if (data && data.icons && Array.isArray(data.icons)) {
                    globalIcons = data.icons;
                } else if (Array.isArray(data)) {
                    globalIcons = data;
                } else {
                    globalIcons = [];
                    for (const [key, val] of Object.entries(data)) { globalIcons.push({ name: key, url: val }); }
                }
                renderIconGrid('');
            } catch(e) { 
                grid.innerHTML = '<div style="grid-column: 1/-1; color: var(--danger); font-size: 13px; text-align: center;">获取图标库失败，请检查链接或网络状态</div>';
            }
        }

        function setCustomIconLibrary() {
            const url = document.getElementById('customIconUrlInput').value.trim();
            if (!url) return showToast('⚠️ 请输入图标库 JSON 链接');
            if (!url.startsWith('http')) return showToast('⚠️ 请输入合法的 URL');
            localStorage.setItem('custom_icon_url', url);
            showToast('⏳ 正在加载自定义图标库...');
            loadIcons(url);
        }

        function resetIconLibrary() {
            localStorage.removeItem('custom_icon_url');
            document.getElementById('customIconUrlInput').value = '';
            showToast('🔄 已恢复默认图标库');
            loadIcons(DEFAULT_ICON_URL);
        }

        function renderIconGrid(filterText) {
            const grid = document.getElementById('iconGrid');
            const lowerFilter = filterText.toLowerCase();
            const filtered = globalIcons.filter(item => (item.name || '').toLowerCase().includes(lowerFilter));
            let html = \`<div class="icon-item" onclick="selectIcon('', '默认 🎬')" title="使用默认图标"><span style="font-size:22px;">🎬</span></div>\`;
            filtered.forEach(item => {
                html += \`<div class="icon-item" onclick="selectIcon('\${item.url}', '\${item.name}')" title="\${item.name}">
                            <img src="\${item.url}" loading="lazy" style="width: 32px; height: 32px; object-fit: contain; border-radius: 4px;">
                        </div>\`;
            });
            grid.innerHTML = html;
        }

        function filterIcons() { renderIconGrid(document.getElementById('iconSearch').value); }

        function toggleIconPicker(e) {
            e.stopPropagation();
            const panel = document.getElementById('iconPickerPanel');
            panel.style.display = panel.style.display === 'none' ? 'flex' : 'none';
        }

        function selectIcon(url, name) {
            document.getElementById('iconUrl').value = url;
            const preview = document.getElementById('iconPreview');
            const def = document.getElementById('iconDefault');
            const text = document.getElementById('iconSelectText');
            if(url) {
                preview.src = url; preview.style.display = 'block'; def.style.display = 'none';
                text.textContent = name; text.style.color = 'var(--text)';
            } else {
                preview.src = ''; preview.style.display = 'none'; def.style.display = 'block';
                text.textContent = '点击选择图标 (默认 🎬)'; text.style.color = 'var(--text-sec)';
            }
            document.getElementById('iconPickerPanel').style.display = 'none';
        }

        document.addEventListener('click', (e) => {
            const panel = document.getElementById('iconPickerPanel');
            const btn = document.getElementById('iconSelectBtn');
            if (panel && btn && panel.style.display !== 'none') {
                if (!panel.contains(e.target) && !btn.contains(e.target)) panel.style.display = 'none';
            }
        });

        function toggleDarkMode() {
            const isDark = document.body.classList.toggle('dark');
            document.getElementById('themeToggle').textContent = isDark ? '☀️' : '🌙';
            localStorage.setItem('emby_proxy_dark', isDark ? '1' : '0');
            if(trendChartInstance) { updateChartColors(); trendChartInstance.update(); locationChartInstance.update(); }
        }
        if (localStorage.getItem('emby_proxy_dark') === '1') { document.body.classList.add('dark'); document.getElementById('themeToggle').textContent = '☀️'; }

        function showToast(msg) {
            const t = document.getElementById('toast');
            t.textContent = msg; t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 3000);
        }

        function copyText(text) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => showToast('已复制: ' + text)).catch(() => showToast('复制失败'));
            } else {
                const ta = document.createElement('textarea');
                ta.value = text; document.body.appendChild(ta); ta.select();
                try { document.execCommand('copy'); showToast('已复制: ' + text); } catch(e) { showToast('复制失败'); }
                document.body.removeChild(ta);
            }
        }



        async function purgeCache() {
            if(!confirm('确定要清理 Cloudflare 节点的全站海报和静态缓存吗？\\n\\n清理后可能导致短时间的加载缓慢。')) return;
            const btn = document.getElementById('btnPurge');
            const originalText = btn.textContent;
            btn.textContent = '⏳ 正在清理...'; btn.disabled = true;
            try {
                const res = await fetch('/api/purge-cache', { method: 'POST' });
                const data = await res.json();
                if(data.success) showToast('✅ 缓存清理成功，新海报已生效！');
                else showToast('❌ 清理失败: ' + data.error);
            } catch(e) { showToast('❌ 网络请求错误'); } finally { btn.textContent = originalText; btn.disabled = false; }
        }

        function filterNodesList() {
            const filterText = document.getElementById('searchNode').value.toLowerCase();
            const cards = document.querySelectorAll('.emby-card');
            cards.forEach(card => {
                const searchStr = card.getAttribute('data-search').toLowerCase();
                card.style.display = searchStr.includes(filterText) ? 'flex' : 'none';
            });
        }

        function handleTargetInputs() {
            const container = document.getElementById('targetInputs');
            const inputs = container.querySelectorAll('.target-input');
            const lastInput = inputs[inputs.length - 1];
            if (lastInput.value.trim() !== '') {
                const newInput = document.createElement('input');
                newInput.type = 'url'; newInput.className = 'target-input';
                newInput.style = 'padding: 10px 14px; border: 1px solid var(--border-solid); border-radius: 8px; background:var(--card-solid); width: 100%;';
                newInput.oninput = handleTargetInputs;
                container.appendChild(newInput);
            }
            let emptyCount = 0;
            const currentInputs = container.querySelectorAll('.target-input');
            for (let i = currentInputs.length - 1; i >= 0; i--) {
                if (currentInputs[i].value.trim() === '') { emptyCount++; if (emptyCount > 1) currentInputs[i].remove(); } else { break; }
            }
            container.querySelectorAll('.target-input').forEach((inp, idx) => {
                inp.placeholder = idx === 0 ? "主线路地址 (如: http://1.1.1.1:8096)" : \`备用线路 \${idx} (选填，主源挂掉时触发)\`;
            });
        }

        function resetTargetInputs() {
            const container = document.getElementById('targetInputs');
            container.innerHTML = \`
                <input type="url" class="target-input" placeholder="主线路地址 (如: http://1.1.1.1:8096)" style="padding: 10px 14px; border: 1px solid var(--border-solid); border-radius: 8px; background:var(--card-solid); width: 100%;" required oninput="handleTargetInputs()">
                <input type="url" class="target-input" placeholder="备用线路 1 (选填)" style="padding: 10px 14px; border: 1px solid var(--border-solid); border-radius: 8px; background:var(--card-solid); width: 100%;" oninput="handleTargetInputs()">
            \`;
        }

        function toggleVis(id, isArray = false) {
            const el = document.getElementById(id);
            if (el.classList.contains('secret-text')) {
                el.classList.remove('secret-text'); el.classList.add('actual-text');
                if (isArray) {
                    const arr = JSON.parse(decodeURIComponent(el.getAttribute('data-val')));
                    let html = '';
                    arr.forEach((t, i) => {
                        const tag = i === 0 ? '<span style="color:var(--success);font-weight:bold;">[主]</span>' : '<span style="color:var(--warning);font-weight:bold;">[备]</span>';
                        html += \`<div class="url-list-item">\${tag} \${t}</div>\`;
                    });
                    el.innerHTML = html;
                } else { el.textContent = el.getAttribute('data-val'); }
            } else {
                el.classList.add('secret-text'); el.classList.remove('actual-text'); el.textContent = '••••••••';
            }
        }

        function copyTxt(txt) { navigator.clipboard.writeText(txt).then(() => showToast('🚀 复制成功！')); }

        async function pingTarget(idx, targetUrl, prefix) {
            const pingEl = document.getElementById('ping-' + idx);
            pingEl.textContent = '测速中...'; pingEl.style.color = 'var(--text-sec)';
            try {
                const res = await fetch('/api/ping-node?url=' + encodeURIComponent(targetUrl) + (prefix ? '&prefix=' + encodeURIComponent(prefix) : ''));
                const data = await res.json();
                if(data.ms >= 0) {
                    pingEl.textContent = data.ms + ' ms';
                    pingEl.style.color = data.ms < 200 ? 'var(--success)' : (data.ms < 500 ? 'var(--primary)' : 'var(--warning)');
                } else { pingEl.textContent = '断连/超时'; pingEl.style.color = 'var(--danger)'; }
            } catch(e) { pingEl.textContent = '测速异常'; pingEl.style.color = 'var(--danger)'; }
        }

        function pingAllNodes() {
            if (proxyNodesForPing.length === 0) return showToast('⚠️ 没有可供测速的反代节点');
            showToast('⚡ 正在对所有节点发起测速...');
            proxyNodesForPing.forEach((node, offset) => { setTimeout(() => pingTarget(node.idx, node.url, node.prefix), offset * 200); });
        }

        async function runDomainSpeedTest() {
            const box = document.getElementById('domainSpeedResult');
            if (!box) return;
            box.innerHTML = '<div style="color:var(--text-sec);font-size:13px;">测速中...</div>';
            try {
                const res = await fetch('/api/domains/speed');
                const data = await res.json();
                if (!data.success) throw new Error(data.error || '测速失败');
                const rows = (data.results || []).map(r => {
                    const ms = (r.ms == null || r.ms >= 9999) ? '超时' : r.ms + 'ms';
                    const color = (r.ms != null && r.ms < 100) ? 'var(--success)' : (r.ms != null && r.ms < 300) ? 'var(--warning)' : 'var(--danger)';
                    const barW = Math.min(100, Math.round((r.ms || 9999) / 6)) + '%';
                    return \`<div style="display:flex;align-items:center;gap:10px;font-size:13px;">
                        <div style="width:150px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="\${escapeHtml(r.host)}">\${escapeHtml(r.name)}</div>
                        <div style="flex:1;height:8px;background:rgba(120,120,120,0.1);border-radius:4px;overflow:hidden;">
                            <div style="width:\${barW};height:100%;background:\${color};border-radius:4px;"></div>
                        </div>
                        <div style="width:64px;text-align:right;font-family:'SF Mono',monospace;color:\${color};font-weight:600;">\${ms}</div>
                        <button class="icon-btn" onclick="copyTxt('https://\${r.host}')" title="复制域名">📋</button>
                    </div>\`;
                }).join('');
                const best = data.best ? \`<div style="margin-top:10px;font-size:13px;font-weight:700;color:var(--success);">🏆 最快：\${escapeHtml(data.best)}</div>\` : '';
                const cached = data.cached ? '<span style="font-size:11px;color:var(--text-sec);">（网段缓存）</span>' : '';
                box.innerHTML = (rows || '<div style="color:var(--text-sec);">无结果</div>') + best + cached;
            } catch (e) {
                box.innerHTML = '<div style="color:var(--danger);font-size:13px;">❌ ' + escapeHtml(e.message) + '</div>';
            }
        }

        async function exportConfig() {
            try {
                const res = await fetch('/api/routes'); const data = await res.json();
                const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = 'emby_proxy_backup.json'; a.click();
                URL.revokeObjectURL(url); showToast('✅ 配置已导出');
            } catch (e) { showToast('❌ 导出失败'); }
        }

        function importConfig() {
            const input = document.createElement('input'); input.type = 'file'; input.accept = '.json';
            input.onchange = async (e) => {
                const file = e.target.files[0]; const reader = new FileReader();
                reader.onload = async (event) => {
                    try {
                        const routes = JSON.parse(event.target.result);
                        const res = await fetch('/api/routes/import', { method: 'POST', body: JSON.stringify(routes) });
                        const result = await res.json();
                        if (result.success) { showToast('✅ 配置导入成功'); load(); } else throw new Error(result.error);
                    } catch (err) { showToast('❌ 导入失败: ' + err.message); }
                };
                reader.readAsText(file);
            };
            input.click();
        }

        async function load() {
            try {
                let healthData = {};
                
                const res = await fetch('/api/routes');
                if (!res.ok) throw new Error('请求失败，请检查环境配置');
                const data = await res.json();
                if (data.error) throw new Error(data.error);

                // 🌟 新增：把节点流量数据存进全局内存，供大屏瞬间读取！
                window.globalRoutesData = data;
                window.globalHealthData = healthData;

                const container = document.getElementById('list-grid');
                if(data.length === 0) {
                    container.innerHTML = '<div style="text-align:center; color:var(--text-sec); grid-column: 1 / -1; padding: 40px;">暂无配置任何反代节点，请先部署一个。</div>';
                    return;
                }
                
                container.innerHTML = '';
                proxyNodesForPing = []; 
                const currentHost = window.location.host;
                // 优先使用 CF_DOMAIN 配置，否则使用当前域名
                const proxyHost = (typeof CF_DOMAIN !== 'undefined' && CF_DOMAIN) ? CF_DOMAIN : currentHost;

                data.forEach((r, idx) => {
                    const proxyUrl = 'https://' + proxyHost + '/' + r.prefix;
                    const targets = r.target.split(',').map(s => s.trim()).filter(Boolean);
                    const mainTarget = targets[0]; 
                    
                    const remarkName = r.remark || '未命名媒体库';
                    const lastPlay = r.last_play ? r.last_play : '暂无播放记录';
                    
                    const iconHtml = r.icon ? \`<img src="\${r.icon}" style="width:24px;height:24px;border-radius:6px;object-fit:cover;" onerror="this.style.display='none'; this.parentElement.innerHTML='🎬';">\` : '🎬';
                    const encodedTargets = encodeURIComponent(JSON.stringify(targets));
                    
                    const todayBw = r.todayBandwidth || '0 B';
                    const totalReqs = r.totalReqs || r.todayReqs || 0;

                    proxyNodesForPing.push({ idx: idx, url: mainTarget, prefix: r.prefix });

                    container.innerHTML += \`
                    <div class="emby-card route-item" data-prefix="\${r.prefix}" data-search="\${remarkName} \${r.prefix}">
                        <div class="card-header">
                            <div class="card-title-group">
                                <div class="drag-handle" title="长按拖拽排序">☰</div>
                                <input type="checkbox" class="node-cb ip-checkbox" value="\${r.prefix}">
                                <div class="emby-icon">\${iconHtml}</div>
                                <div>
                                    <div style="font-weight: 600; font-size: 15px;">\${remarkName}</div>
                                    <div style="font-size: 12px; color: var(--text-sec); margin-top:1px;">/\${r.prefix}</div>
                                </div>
                            </div>
                            <span class="badge" style="background: rgba(16,185,129,0.08); color: var(--primary);">\${modeNames[r.mode] || '未知'}</span>
                        </div>

                        <div class="node-stats">
                            <div class="node-stat-item">
                                <span class="node-stat-label">⬇️ 今日流量</span>
                                <span class="node-stat-value" style="color:var(--primary);">\${todayBw}</span>
                            </div>
                            <div class="node-stat-item">
                                <span class="node-stat-label">📺 播放 (今日/累计)</span>
                                <span class="node-stat-value" style="color:var(--warning);">\${r.todayReqs} / \${totalReqs}</span>
                            </div>
                        </div>

                        <details class="node-details">
                            <summary>查看详情</summary>
                            <div class="node-details-body">
                        <div style="display: flex; flex-direction: column; gap: 8px;">
                            <div class="info-row">
                                <span class="info-label">节点延迟:</span>
                                <span id="ping-\${idx}" class="ping-badge" onclick="pingTarget(\${idx}, '\${mainTarget}', '\${r.prefix}')" title="点击重新测速">测速中...</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">海报缓存:</span>
                                <span style="color:\${r.cache_img !== 'off' ? 'var(--success)' : 'var(--warning)'}; font-weight:600; font-size: 12px;">\${r.cache_img !== 'off' ? '✅ 已开启' : '❌ 已关闭'}</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">最后活跃:</span>
                                <span style="color:var(--text-sec); font-size: 12px;">\${lastPlay}</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">直达链接:</span>
                                <div class="action-group" style="flex:1; justify-content: flex-end; margin-left: 8px; align-items: flex-start;">
                                    <span id="p-\${idx}" data-val="\${proxyUrl}" class="secret-text dynamic-url">••••••••</span>
                                    <button class="icon-btn" onclick="toggleVis('p-\${idx}')" title="查看明文"><svg viewBox=\"0 0 24 24\" style=\"width:16px;height:16px;fill:currentColor\"><path d=\"M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z\"/></svg></button>
                                    <button class="icon-btn" onclick="copyTxt('\${proxyUrl}')" title="复制链接"><svg viewBox=\"0 0 24 24\" style=\"width:16px;height:16px;fill:currentColor\"><path d=\"M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z\"/></svg></button>
                                </div>
                            </div>
                            <div class="info-row">
                                <span class="info-label">源站线路:</span>
                                <div class="action-group" style="flex:1; justify-content: flex-end; margin-left: 8px; align-items: flex-start;">
                                    <div id="t-\${idx}" data-val="\${encodedTargets}" class="secret-text dynamic-url">••••••••</div>
                                    <button class="icon-btn" onclick="toggleVis('t-\${idx}', true)" title="查看明文"><svg viewBox=\"0 0 24 24\" style=\"width:16px;height:16px;fill:currentColor\"><path d=\"M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z\"/></svg></button>
                                </div>
                            </div>

                        <div class="card-footer">
                            <button class="btn-edit" onclick="editNode('\${r.prefix}', '\${r.target}', '\${r.mode}', '\${r.remark || ''}', '\${r.icon || ''}', '\${r.cache_img}')">编辑配置</button>
                            <button class="btn-del" onclick="del('\${r.prefix}')">删除</button>
                        </div>
                            </div>
                        </details>
                    </div>\`;

                    setTimeout(() => pingTarget(idx, mainTarget), 500 * idx); 
                });
                
                filterNodesList();

                if (sortableInstance) sortableInstance.destroy();
                sortableInstance = Sortable.create(container, {
                    handle: '.drag-handle',
                    animation: 150,
                    delay: 200, 
                    delayOnTouchOnly: true,
                    onEnd: async function () {
                        const items = [];
                        container.querySelectorAll('.route-item').forEach((row, index) => {
                            const prefix = row.getAttribute('data-prefix');
                            if (prefix) items.push({ prefix: prefix, sort_order: index });
                        });
                        try {
                            await fetch('/api/routes/reorder', { method: 'POST', body: JSON.stringify(items) });
                            showToast('✅ 排序已保存');
                        } catch(e) { showToast('❌ 排序保存失败'); }
                    }
                });

            } catch (err) {
                document.getElementById('list-grid').innerHTML = \`<div style="text-align:center; color:var(--danger); font-weight:600; grid-column: 1 / -1; padding: 20px;">⚠️ 读取失败: \${err.message}</div>\`;
            }
        }

        function editNode(prefix, targetStr, mode, remark, icon, cacheImg) {
            document.getElementById('oldPrefix').value = prefix;
            document.getElementById('remark').value = remark;
            document.getElementById('prefix').value = prefix;
            document.getElementById('mode').value = mode || 'off';
            document.getElementById('nodeCache').checked = (cacheImg !== 'off');
            
            if (icon) {
                const foundItem = globalIcons.find(i => i.url === icon);
                selectIcon(icon, foundItem ? foundItem.name : '已选择图标');
            } else {
                selectIcon('', '默认 🎬');
            }

            document.getElementById('submitBtn').textContent = '保存修改';
            
            const container = document.getElementById('targetInputs');
            container.innerHTML = '';
            const targets = targetStr.split(',').map(s => s.trim()).filter(Boolean);
            
            targets.forEach((url) => {
                const inp = document.createElement('input');
                inp.type = 'url'; inp.className = 'target-input'; inp.value = url;
                inp.style = 'padding: 10px 14px; border: 1px solid var(--border-solid); border-radius: 8px; background:var(--card-solid); width: 100%;';
                inp.oninput = handleTargetInputs;
                container.appendChild(inp);
            });
            
            const emptyInp = document.createElement('input');
            emptyInp.type = 'url'; emptyInp.className = 'target-input';
            emptyInp.style = 'padding: 10px 14px; border: 1px solid var(--border-solid); border-radius: 8px; background:var(--card-solid); width: 100%;';
            emptyInp.oninput = handleTargetInputs;
            container.appendChild(emptyInp);
            
            handleTargetInputs(); 
            window.scrollTo({ top: document.getElementById('addForm').offsetTop - 100, behavior: 'smooth' });
        }

        document.getElementById('addForm').onsubmit = async (e) => {
            e.preventDefault();
            const oldPrefix = document.getElementById('oldPrefix').value;
            const remark = document.getElementById('remark').value.trim();
            const prefix = document.getElementById('prefix').value.trim().replace(/^\\/+/g, '');
            const mode = document.getElementById('mode').value;
            const icon = document.getElementById('iconUrl').value;
            const cache_img = document.getElementById('nodeCache').checked ? 'on' : 'off';

            const inputs = document.querySelectorAll('.target-input');
            let targetsArray = [];
            inputs.forEach(inp => {
                const val = inp.value.trim().replace(/\\/$/g, '');
                if (val) targetsArray.push(val);
            });
            const target = targetsArray.join(',');
            
            if (!target) return showToast('❌ 请至少填写一个主线路地址');

            try {
                const res = await fetch('/api/routes', { 
                    method: 'POST', 
                    body: JSON.stringify({oldPrefix, prefix, target, mode, remark, icon, cache_img})
                });
                const data = await res.json();
                if(!data.success) throw new Error(data.error || '部署失败');
                
                document.getElementById('addForm').reset();
                document.getElementById('oldPrefix').value = ''; 
                selectIcon('', '默认 🎬');
                document.getElementById('nodeCache').checked = true;
                document.getElementById('submitBtn').textContent = '保存部署'; 
                resetTargetInputs(); 
                
                showToast('✅ 节点部署成功');
                load();
            } catch(err) {
                showToast('❌ 保存失败: ' + err.message);
            }
        };

        async function del(prefix) {
            if(confirm('确定删除节点 /' + prefix + ' ?')) {
                await fetch('/api/routes?prefix=' + prefix, { method: 'DELETE' });
                showToast('🗑️ 节点已移除');
                load();
            }
        }

        function toggleSelectAll() {
            const isChecked = document.getElementById('selectAll').checked;
            document.querySelectorAll('.row-checkbox').forEach(cb => {
                if(!cb.disabled) cb.checked = isChecked;
            });
        }
        function getSelectedIps() {
            const checkboxes = document.querySelectorAll('.row-checkbox:checked');
            return Array.from(checkboxes).map(cb => cb.value);
        }
        function batchTcpPing() {
            const rows = document.querySelectorAll('#testTableBody .test-row');
            let ips = [];
            rows.forEach(tr => {
                const strong = tr.querySelector('.ip-text');
                if (strong && strong.textContent) {
                    let ip = strong.textContent;
                    if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
                    ips.push(ip);
                }
            });
            if (ips.length === 0) return showToast('⚠️ 请先提取节点！');
            navigator.clipboard.writeText(ips.join('\\n')).then(() => {
                showToast('✅ 节点已复制，即将跳转 ITDog...');
                setTimeout(() => { window.open('https://www.itdog.cn/batch_tcping/', '_blank'); }, 1500);
            });
        }
        function directSubmitCname() {
            const input = document.getElementById('customIps').value.trim();
            if (!input) return showToast('⚠️ 请先在文本框内粘贴您的优选域名');
            const domainRegex = /\\b([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}\\b/g;
            const matchedDomains = input.match(domainRegex) || [];
            const realDomains = matchedDomains.filter(d => !/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(d));
            if (realDomains.length === 0) return showToast('⚠️ 没有提取到合法的域名格式，请检查输入！');
            if(!confirm(\`✨ 提取到以下域名：\\n\${realDomains.join('\\n')}\\n\\n确定要直接将其设为 CNAME 记录吗？\\n(注意：这会清空你配置的域名下现有的记录)\`)) return;
            const btn = document.getElementById('btnDirectCname');
            sendDnsRequest(realDomains, btn);
        }
        async function testCustomIPs() {
            const input = document.getElementById('customIps').value;
            if (!input.trim()) return showToast('⚠️ 请先在输入框粘贴 IP 或优选域名');
            const ipv4Regex = /\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b/g;
            const ipv6Regex = /(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?:[A-F0-9]{1,4}:)*:[A-F0-9]{1,4}(?::[A-F0-9]{1,4})*/gi;
            const domainRegex = /\\b([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}\\b/g;
            let matchedIPv4 = input.match(ipv4Regex) || [];
            let matchedIPv6 = input.match(ipv6Regex) || [];
            let matchedDomains = input.match(domainRegex) || [];
            matchedDomains = matchedDomains.filter(d => !/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(d));
            let extractedIps = [...matchedIPv4, ...matchedDomains];
            matchedIPv6.forEach(ip => {
                if (ip.length > 7 && ip.includes(':') && !ip.startsWith('::1')) { extractedIps.push(ip.startsWith('[') ? ip : \`[\${ip}]\`); }
            });
            extractedIps = [...new Set(extractedIps)];
            if (extractedIps.length === 0) return showToast('⚠️ 未识别到合法的 IP 或 域名格式');
            const btn = document.getElementById('btnTestCustom');
            const tbody = document.getElementById('testTableBody');
            btn.disabled = true; btn.textContent = '⏳ 测试中...';
            if(tbody.innerHTML.includes('暂无数据')) tbody.innerHTML = '';
            showToast(\`✅ 提取到 \${extractedIps.length} 个节点，开始测速校验\`);
            const promises = [];
            extractedIps.forEach(ip => {
                const tr = document.createElement('tr');
                tr.className = 'test-row';
                tr.innerHTML = \`
                    <td data-label="勾选节点" style="text-align: center;"><input type="checkbox" class="ip-checkbox row-checkbox" value="\${ip}"></td>
                    <td data-label="专属节点"><strong class="ip-text" style="color:var(--primary);cursor:pointer;font-family:'SF Mono',monospace;font-size:12px;" onclick="copyTxt('\${ip}')" title="点击复制">\${ip}</strong></td>
                    <td data-label="预估延迟" class="latency" data-ms="9999" style="font-weight: 600; color: var(--text-sec);">测算中...</td>
                    <td data-label="连通状态" class="speed" style="color: var(--text-sec);">-</td>
                    <td data-label="记录/归属地" class="loc" style="color: var(--text-sec);">等待解析</td>
                    <td data-label="快捷操作"><button class="btn-dns" disabled onclick="updateSingleDns('\${ip}', this)">唯一解析</button></td>\`;
                tbody.insertBefore(tr, tbody.firstChild);
                promises.push(doLocalPing(ip, tr, '自定义节点'));
            });
            await Promise.all(promises);
            sortTableByLatency(tbody);
            document.querySelectorAll('.btn-dns').forEach(b => b.disabled = false);
            btn.disabled = false; btn.textContent = '🧪 测试粘贴的节点';
            showToast('🎉 自定义节点测速完成！');
        }
        async function fetchCustomApiAndTest() {
            const apiUrl = document.getElementById('customApiUrl').value.trim();
            if (!apiUrl) return showToast('⚠️ 请先填入自定义 API 链接');
            const btn = document.getElementById('btnFetchCustomApi');
            const tbody = document.getElementById('testTableBody');
            const statusTxt = document.getElementById('statusText');
            btn.disabled = true; btn.textContent = '⏳ 拉取中...';
            statusTxt.innerHTML = \`正在从自定义 API 抓取数据...\`;
            if(tbody.innerHTML.includes('暂无数据')) tbody.innerHTML = ''; 
            try {
                const res = await fetch(\`/api/get-custom-api-ips?url=\${encodeURIComponent(apiUrl)}\`);
                const data = await res.json();
                if (!data.ips || data.ips.length === 0) { showToast('⚠️ 自定义 API 返回为空'); return; }
                showToast(\`✅ 提取 \${data.totalCount} 个节点，抽取 \${data.ips.length} 个测速\`);
                btn.textContent = '⚡ 测速中...';
                const promises = [];
                data.ips.forEach(ip => {
                    const tr = document.createElement('tr');
                    tr.className = 'test-row';
                    tr.innerHTML = \`
                        <td data-label="勾选节点" style="text-align: center;"><input type="checkbox" class="ip-checkbox row-checkbox" value="\${ip}"></td>
                        <td data-label="专属节点"><strong class="ip-text" style="color:var(--primary);cursor:pointer;font-family:'SF Mono',monospace;font-size:12px;" onclick="copyTxt('\${ip}')" title="点击复制">\${ip}</strong></td>
                        <td data-label="预估延迟" class="latency" data-ms="9999" style="font-weight: 600; color: var(--text-sec);">测算中...</td>
                        <td data-label="连通状态" class="speed" style="color: var(--text-sec);">-</td>
                        <td data-label="记录/归属地" class="loc" style="color: var(--text-sec);">等待解析</td>
                        <td data-label="快捷操作"><button class="btn-dns" disabled onclick="updateSingleDns('\${ip}', this)">唯一解析</button></td>\`;
                    tbody.insertBefore(tr, tbody.firstChild);
                    promises.push(doLocalPing(ip, tr, '自定义 API'));
                });
                await Promise.all(promises);
                sortTableByLatency(tbody);
                document.querySelectorAll('.btn-dns').forEach(b => b.disabled = false);
                document.getElementById('selectAll').checked = false;
                showToast('🎉 自定义 API 测速完成！');
                statusTxt.innerHTML = \`✅ 测速完毕！您可以自由组合更新 DNS。\`;
            } catch (err) { showToast('❌ 拉取失败'); } 
            finally { btn.disabled = false; btn.textContent = '🌐 拉取 API 并测速'; }
        }
        async function fetchRemoteAndTest() {
            const btn = document.getElementById('btnFetchRemote');
            const tbody = document.getElementById('testTableBody');
            const statusTxt = document.getElementById('statusText');
            const type = document.getElementById('ipType').value;
            const typeText = document.getElementById('ipType').options[document.getElementById('ipType').selectedIndex].text;
            btn.disabled = true; btn.textContent = '⏳ 正在提取节点...';
            statusTxt.innerHTML = \`正在拉取 <strong>\${typeText}</strong> 数据...\`;
            if(tbody.innerHTML.includes('暂无数据')) tbody.innerHTML = ''; 
            try {
                const res = await fetch(\`/api/get-remote-ips?type=\${encodeURIComponent(type)}\`);
                const data = await res.json();
                if (!data.ips || data.ips.length === 0) { showToast('⚠️ 未获取到该类型 IP'); return; }
                showToast(\`✅ 成功提取 \${data.totalCount} 个可用 IP，抽取 \${data.ips.length} 个测速\`);
                btn.textContent = '⚡ 本地测速中...';
                const promises = [];
                data.ips.forEach(ip => {
                    const tr = document.createElement('tr');
                    tr.className = 'test-row';
                    tr.innerHTML = \`
                        <td data-label="勾选节点" style="text-align: center;"><input type="checkbox" class="ip-checkbox row-checkbox" value="\${ip}"></td>
                        <td data-label="专属节点"><strong class="ip-text" style="color:var(--primary);cursor:pointer;font-family:'SF Mono',monospace;font-size:12px;" onclick="copyTxt('\${ip}')" title="点击复制">\${ip}</strong></td>
                        <td data-label="预估延迟" class="latency" data-ms="9999" style="font-weight: 600; color: var(--text-sec);">测算中...</td>
                        <td data-label="连通状态" class="speed" style="color: var(--text-sec);">-</td>
                        <td data-label="记录/归属地" class="loc" style="color: var(--text-sec);">等待解析</td>
                        <td data-label="快捷操作"><button class="btn-dns" disabled onclick="updateSingleDns('\${ip}', this)">唯一解析</button></td>\`;
                    tbody.insertBefore(tr, tbody.firstChild);
                    promises.push(doLocalPing(ip, tr, typeText.replace(/[^\u4e00-\u9fa5a-zA-Z0-9]/g, '')));
                });
                await Promise.all(promises);
                sortTableByLatency(tbody);
                document.querySelectorAll('.btn-dns').forEach(b => b.disabled = false);
                document.getElementById('selectAll').checked = false;
                showToast('🎉 测速完成！');
                statusTxt.innerHTML = \`✅ 测速完毕！\`;
            } catch (err) { showToast('❌ 拉取或测速失败'); } 
            finally { btn.disabled = false; btn.textContent = '🌍 提取预设源并测速'; }
        }
        function clearTest() {
            document.getElementById('testTableBody').innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-sec);">暂无数据，请拉取节点或输入自定义 IP/域名 测试</td></tr>';
            document.getElementById('statusText').textContent = '列表已清空。';
            document.getElementById('selectAll').checked = false;
        }
        function markTimeout(latTd, spdTd, tr) {
            latTd.textContent = '超时抛弃'; latTd.setAttribute('data-ms', 9999); latTd.style.color = 'var(--danger)';
            spdTd.textContent = '❌ 超时 (>2000ms)'; spdTd.style.color = 'var(--danger)';
            const cb = tr.querySelector('.row-checkbox');
            if(cb) { cb.disabled = true; cb.title = '不可用的节点无法被勾选'; }
        }
        async function doLocalPing(ip, tr, sourceLabel) {
            const latTd = tr.querySelector('.latency');
            const spdTd = tr.querySelector('.speed');
            const locTd = tr.querySelector('.loc');
            const queryIp = ip.replace(/[\\[\\]]/g, '');
            const isIPv6 = ip.includes(':'); 
            const isDomain = /[a-zA-Z]/.test(queryIp) && !isIPv6;
            if (isDomain) { locTd.innerHTML = \`<span class="badge" style="background:rgba(168,85,247,0.1);color:#a855f7;margin-right:4px;">CNAME</span> \${sourceLabel} | 优选域名\`;
            } else {
                const recordLabel = isIPv6 ? '<span class="badge" style="background:rgba(59,130,246,0.1);color:#3b82f6;margin-right:4px;">AAAA</span>' : '<span class="badge" style="background:rgba(16,185,129,0.1);color:var(--primary);margin-right:4px;">A记录</span>';
                fetch(\`https://api.ip.sb/geoip/\${queryIp}\`).then(res => res.json()).then(data => locTd.innerHTML = \`\${recordLabel} \${sourceLabel} | \${data.country || '未知'}\`).catch(() => locTd.innerHTML = \`\${recordLabel} \${sourceLabel} | 解析失败\`);
            }
            const start = performance.now();
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000); 
            const processResult = () => {
                const rawLatency = Math.round(performance.now() - start);
                if (rawLatency > 2000) return markTimeout(latTd, spdTd, tr);
                let displayLatency = rawLatency;
                if (!isIPv6 && !isDomain) {
                    if (rawLatency >= 500) { displayLatency = rawLatency - 400; } 
                    else { const base = 40 + (rawLatency / 500) * 60; displayLatency = Math.floor(base) + Math.floor(Math.random() * 10); }
                }
                updateRowState(latTd, spdTd, displayLatency);
            };
            try { await fetch(\`https://\${ip}/cdn-cgi/trace\`, { mode: 'no-cors', signal: controller.signal }); clearTimeout(timeoutId); processResult();
            } catch (err) { clearTimeout(timeoutId); if (err.name === 'AbortError') markTimeout(latTd, spdTd, tr); else processResult(); }
        }
        function updateRowState(latTd, spdTd, latency) {
            latTd.textContent = latency + ' ms'; latTd.setAttribute('data-ms', latency);
            if (latency < 300) { latTd.style.color = 'var(--success)'; spdTd.textContent = '🚀 极佳'; spdTd.style.color = 'var(--success)'; } 
            else if (latency <= 500) { latTd.style.color = 'var(--primary)'; spdTd.textContent = '✅ 正常'; spdTd.style.color = 'var(--primary)'; } 
            else { latTd.style.color = 'var(--warning)'; spdTd.textContent = '⚠️ 较高'; spdTd.style.color = 'var(--warning)'; }
        }
        function sortTableByLatency(tbody) {
            const rows = Array.from(tbody.querySelectorAll('.test-row'));
            rows.sort((a, b) => {
                const msA = parseInt(a.querySelector('.latency').getAttribute('data-ms') || 9999);
                const msB = parseInt(b.querySelector('.latency').getAttribute('data-ms') || 9999);
                return msA - msB;
            });
            rows.forEach(row => tbody.appendChild(row));
        }
        async function sendDnsRequest(ips, btnElement) {
            const originalText = btnElement.textContent;
            btnElement.textContent = '🔄 更新 DNS 中...'; btnElement.disabled = true;
            try {
                const res = await fetch('/api/update-dns', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ips }) });
                const data = await res.json();
                if(data.success) { showToast(data.message); btnElement.textContent = '✅ 更新成功'; loadDNS(); } 
                else { showToast('❌ 错误: ' + (data.error || '')); btnElement.textContent = originalText; }
            } catch(e) { showToast('❌ 网络异常，请重试'); btnElement.textContent = originalText; } 
            finally { setTimeout(() => { if(btnElement.textContent === '✅ 更新成功') btnElement.textContent = originalText; btnElement.disabled = false; }, 3000); }
        }
        function updateSingleDns(ip, btnElement) {
            if(!confirm(\`确定要将域名解析到：\\n\${ip} \\n警告：这会覆盖域名下的所有解析记录！\`)) return;
            sendDnsRequest([ip], btnElement);
        }
        function updateSelectedToDns() {
            const btn = document.getElementById('btnSelectedDns');
            const ips = getSelectedIps();
            if (ips.length === 0) return showToast('⚠️ 请先勾选您想使用的节点');
            if(!confirm(\`将应用勾选的 \${ips.length} 个节点：\\n\${ips.join('\\n')}\\n确定更新 DNS 记录吗？\`)) return;
            sendDnsRequest(ips, btn);
        }
        function updateTop3ToDns() {
            const btn = document.getElementById('btnTop3Dns');
            const rows = document.querySelectorAll('#testTableBody .test-row');
            let topIps = [];
            for(let i = 0; i < rows.length; i++) {
                const ms = parseInt(rows[i].querySelector('.latency').getAttribute('data-ms'));
                if(ms < 2000) topIps.push(rows[i].querySelector('.ip-text').textContent);
                if(topIps.length === 3) break;
            }
            if(topIps.length === 0) return showToast('⚠️ 没找到可用节点，请先测速');
            if(!confirm(\`将为您分发当前最快的 \${topIps.length} 个节点：\\n\${topIps.join('\\n')}\\n确定更新 DNS 记录吗？\`)) return;
            sendDnsRequest(topIps, btn);
        }
        async function loadDNS() {
            try {
                const res = await fetch('/api/get-dns'); const data = await res.json(); const container = document.getElementById('dnsStatus');
                if (data.success && data.result) {
                    const records = data.result.filter(r => r.type === 'A' || r.type === 'AAAA' || r.type === 'CNAME');
                    if (records.length === 0) container.innerHTML = '<span class="badge" style="background:rgba(245,158,11,0.1);color:var(--warning);">暂无解析记录</span>';
                    else container.innerHTML = records.map(r => \`<span class="badge" style="background:rgba(16,185,129,0.08);color:var(--primary);border:1px solid rgba(16,185,129,0.15);">\${r.type} | \${r.content}</span>\`).join('');
                } else container.innerHTML = \`<span class="badge" style="background:rgba(239,68,68,0.08);color:var(--danger);">\${data.error || '获取失败'}</span>\`;
            } catch (e) { document.getElementById('dnsStatus').innerHTML = '<span class="badge" style="background:rgba(239,68,68,0.08);color:var(--danger);">网络异常</span>'; }
        }
        
        function logout() {
            document.cookie = "admin_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
            window.location.reload();
        }

        // ==========================================
        // 🤖 智能DNS自动更新 - 前端函数
        // ==========================================
        async function manualAutoUpdate() {
            const btn = document.getElementById('btnManualAutoDns');
            const resultDiv = document.getElementById('autoUpdateResult');
            btn.disabled = true; btn.textContent = '⏳ 智能调度中，请耐心等待...';
            resultDiv.style.display = 'block';
            resultDiv.style.background = 'rgba(16,185,129,0.04)';
            resultDiv.style.border = '1px solid rgba(16,185,129,0.15)';
            resultDiv.style.color = 'var(--primary)';
            resultDiv.innerHTML = '🤖 正在拉取移动专属节点并执行多维度智能评分...<br>⏱️ 预计需要 15-30 秒';
            
            try {
                const res = await fetch('/api/auto-dns-update', { method: 'POST' });
                const data = await res.json();
                
                if (data.success) {
                    resultDiv.style.background = 'rgba(34,197,94,0.04)';
                    resultDiv.style.border = '1px solid rgba(34,197,94,0.15)';
                    resultDiv.style.color = 'var(--success)';
                    let html = '✅ ' + data.message + '<br><br>';
                    html += '<strong>🏆 TOP节点详情：</strong><br>';
                    data.topNodes.forEach((n, i) => {
                        const color = i === 0 ? 'var(--danger)' : (i === 1 ? 'var(--warning)' : '#eab308');
                        html += '<span style="color:' + color + ';font-weight:bold;">#' + (i+1) + '</span> ' + n.ip + ' — 延迟: <strong>' + n.latency + 'ms</strong> | 评分: <strong>' + n.score + '</strong><br>';
                    });
                    resultDiv.innerHTML = html;
                    loadDNS();
                } else {
                    resultDiv.style.background = 'rgba(239,68,68,0.04)';
                    resultDiv.style.border = '1px solid rgba(239,68,68,0.15)';
                    resultDiv.style.color = 'var(--danger)';
                    resultDiv.innerHTML = '❌ 更新失败: ' + data.error;
                }
            } catch(e) {
                resultDiv.style.background = 'rgba(239,68,68,0.04)';
                resultDiv.style.border = '1px solid rgba(239,68,68,0.15)';
                resultDiv.style.color = 'var(--danger)';
                resultDiv.innerHTML = '❌ 网络异常: ' + e.message;
            } finally {
                btn.disabled = false; btn.textContent = '🚀 手动触发智能更新';
            }
        }

        async function loadDnsHistory() {
            const panel = document.getElementById('dnsHistoryPanel');
            const content = document.getElementById('dnsHistoryContent');
            
            if (panel.style.display === 'none') {
                panel.style.display = 'block';
                content.innerHTML = '<div style="text-align:center;color:var(--text-sec);padding:20px;">加载中...</div>';
                
                try {
                    const res = await fetch('/api/dns-history');
                    const data = await res.json();
                    
                    if (data.success && data.history && data.history.length > 0) {
                        let html = '';
                        data.history.forEach(h => {
                            const isSuccess = !h.error_msg;
                            let nodes = [];
                            try { nodes = JSON.parse(h.nodes_json || '[]'); } catch(e) { nodes = []; }
                            html += \`<div style="background:var(--border);border:1px solid var(--border);border-radius:10px;padding:12px;margin-bottom:8px;border-left:3px solid \${isSuccess ? 'var(--success)' : 'var(--danger)'};">\`;
                            html += \`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:6px;">\`;
                            html += \`<span style="font-size:12px;color:var(--text-sec);">\${h.created_at}</span>\`;
                            html += \`<span class="badge" style="background:\${isSuccess ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)'};color:\${isSuccess ? 'var(--success)' : 'var(--danger)'};">\${h.trigger_type === 'auto' ? '🤖 自动' : '👤 手动'}</span>\`;
                            html += \`</div>\`;
                            
                            if (isSuccess) {
                                html += \`<div style="font-size:13px;">测试 <strong>\${h.total_tested}</strong> 个节点，<strong>\${h.success_count}</strong> 个可用</div>\`;
                                if (nodes.length > 0) {
                                    html += \`<div style="margin-top:6px;font-size:12px;color:var(--text-sec);">推送节点：</div>\`;
                                    nodes.forEach((n, i) => {
                                        html += \`<div style="font-size:12px;font-family:monospace;color:var(--primary);padding:2px 0;">#\${i+1} \${n.ip} (\${n.latency}ms)</div>\`;
                                    });
                                }
                            } else {
                                html += \`<div style="font-size:13px;color:var(--danger);">❌ \${h.error_msg}</div>\`;
                            }
                            html += \`</div>\`;
                        });
                        content.innerHTML = html;
                    } else {
                        content.innerHTML = '<div style="text-align:center;color:var(--text-sec);padding:20px;">暂无历史记录</div>';
                    }
                } catch(e) {
                    content.innerHTML = '<div style="text-align:center;color:var(--danger);padding:20px;">加载失败</div>';
                }
            } else {
                panel.style.display = 'none';
            }
        }

        async function loadLastUpdateInfo() {
            try {
                const res = await fetch('/api/dns-history');
                const data = await res.json();
                if (data.success && data.history && data.history.length > 0) {
                    const last = data.history[0];
                    const el = document.getElementById('lastUpdateTime');
                    const isSuccess = !last.error_msg;
                    el.textContent = \`上次: \${last.created_at} (\${isSuccess ? '✅成功' : '❌失败'})\`;
                    el.style.color = isSuccess ? 'var(--success)' : 'var(--danger)';
                } else {
                    document.getElementById('lastUpdateTime').textContent = '暂无记录';
                }
            } catch(e) {}
        }

        // 初始化加载 - 并行执行，不阻塞
        load();
        loadDNS();
        loadLastUpdateInfo();
        loadAutoDnsConfig();
        loadSubdomainConfig();
        loadIcons(); // 异步加载图标，不阻塞主流程
        initTgConsole(); // 初始化 Telegram 控制台

        // 加载自动DNS配置
        async function loadAutoDnsConfig() {
            try {
                const res = await fetch('/api/auto-dns-config');
                const data = await res.json();
                if (data.success && data.config) {
                    const cfg = data.config;
                    const ispSelect = document.getElementById('autoDnsIspType');
                    const topNSelect = document.getElementById('autoDnsTopN');
                    const ispDisplay = document.getElementById('autoDnsIsp');
                    const topNDisplay = document.getElementById('autoDnsTopNDisplay');
                    if (ispSelect && cfg.isp) ispSelect.value = cfg.isp;
                    if (topNSelect && cfg.topN) topNSelect.value = cfg.topN;
                    if (ispDisplay && cfg.isp) {
                        const ispMap = { '移动': '🟢 移动专属', '电信': '🔵 电信专属', '联通': '🟠 联通专属', '多线': '🟣 多线BGP', 'ipv6': '🚀 IPv6节点', '优选': '🌟 顶尖优选库', 'all': '🌐 综合混合源' };
                        ispDisplay.textContent = ispMap[cfg.isp] || cfg.isp;
                    }
                    if (topNDisplay && cfg.topN) topNDisplay.textContent = 'TOP ' + cfg.topN;
                }
            } catch(e) { console.error('loadAutoDnsConfig error:', e); }
        }

        // 保存自动DNS配置
        async function saveAutoDnsConfig() {
            const ispType = document.getElementById('autoDnsIspType').value;
            const topN = document.getElementById('autoDnsTopN').value;
            const btn = event.target;
            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = '⏳ 保存中...';
            try {
                const res = await fetch('/api/auto-dns-config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ isp_type: ispType, top_n: parseInt(topN) })
                });
                const data = await res.json();
                if (data.success) {
                    btn.textContent = '✅ 已保存';
                    const ispMap = { '移动': '🟢 移动专属', '电信': '🔵 电信专属', '联通': '🟠 联通专属', '多线': '🟣 多线BGP', 'ipv6': '🚀 IPv6节点', '优选': '🌟 顶尖优选库', 'all': '🌐 综合混合源' };
                    document.getElementById('autoDnsIsp').textContent = ispMap[ispType] || ispType;
                    document.getElementById('autoDnsTopNDisplay').textContent = 'TOP ' + topN;
                    setTimeout(() => { btn.textContent = originalText; btn.disabled = false; }, 1500);
                } else {
                    throw new Error(data.error || '保存失败');
                }
            } catch(e) {
                btn.textContent = '❌ 失败';
                setTimeout(() => { btn.textContent = originalText; btn.disabled = false; }, 1500);
            }
        }

        // ==========================================
        // 🌐 多线子域名调度 UI 逻辑
        // ==========================================
        const SUB_ISP_OPTIONS = ['移动','电信','联通','多线','ipv6','优选','all'];
        const SUB_ISP_MAP = { '移动':'🟢 移动','电信':'🔵 电信','联通':'🟠 联通','多线':'🟣 多线','ipv6':'🚀 IPv6','优选':'🌟 优选','all':'🌐 混合' };

        async function loadSubdomainConfig() {
            try {
                const res = await fetch('/api/subdomain-config');
                const data = await res.json();
                if (!data.success) return;
                const list = document.getElementById('subdomainList');
                if (!list) return;
                const base = data.baseDomain;
                let html = '';
                (data.subs || []).forEach(function(s) {
                    const ispOptions = SUB_ISP_OPTIONS.map(function(o) {
                        return '<option value="' + o + '"' + (o === s.ispType ? ' selected' : '') + '>' + (SUB_ISP_MAP[o] || o) + '</option>';
                    }).join('');
                    const topOptions = [1,2,3,5].map(function(n) {
                        return '<option value="' + n + '"' + (n === s.topN ? ' selected' : '') + '>TOP ' + n + '</option>';
                    }).join('');
                    const icon = s.sub === 'yd' ? '🟢' : (s.sub === 'lt' ? '🟠' : '🔵');
                    html += '<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;background:rgba(120,120,120,0.04);padding:10px 12px;border-radius:10px;border:1px solid var(--border);">'
                        + '<div style="font-weight:700;min-width:120px;"><span style="font-size:16px;">' + icon + '</span> ' + s.sub + '.' + base + '</div>'
                        + '<select class="form-input sub-isp" data-sub="' + s.sub + '" style="width:auto;min-width:120px;font-size:13px;">' + ispOptions + '</select>'
                        + '<select class="form-input sub-topn" data-sub="' + s.sub + '" style="width:auto;min-width:80px;font-size:13px;">' + topOptions + '</select>'
                        + '<label style="display:flex;align-items:center;gap:4px;font-size:13px;cursor:pointer;"><input type="checkbox" class="sub-enabled" data-sub="' + s.sub + '"' + (s.enabled ? ' checked' : '') + '> 启用</label>'
                        + '<button class="btn-dns" onclick="manualSubdomainUpdate(\\'' + s.sub + '\\', this)">单独调度</button>'
                        + '<button class="btn-dns btn-copy" data-copy="' + s.domain + '">复制地址</button>'
                        + '</div>';
                });
                list.innerHTML = html;
            } catch(e) { console.error('loadSubdomainConfig error:', e); }
        }

        // 复制子域名地址（事件委托，避免内联引号转义问题）
        document.addEventListener('click', function(e) {
            const btn = e.target && e.target.closest ? e.target.closest('.btn-copy') : null;
            if (btn && btn.dataset.copy) copyText('https://' + btn.dataset.copy + '/');
        });

        async function saveSubdomainConfig() {
            const list = document.getElementById('subdomainList');
            if (!list) return;
            const subs = [];
            list.querySelectorAll('.sub-isp').forEach(function(sel) {
                const sub = sel.dataset.sub;
                const topN = list.querySelector('.sub-topn[data-sub="' + sub + '"]').value;
                const enabled = list.querySelector('.sub-enabled[data-sub="' + sub + '"]').checked;
                subs.push({ sub: sub, isp_type: sel.value, top_n: parseInt(topN, 10), enabled: enabled });
            });
            const btn = event.target;
            const orig = btn.textContent;
            btn.disabled = true; btn.textContent = '⏳ 保存中...';
            try {
                const res = await fetch('/api/subdomain-config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subs: subs }) });
                const data = await res.json();
                if (data.success) { btn.textContent = '✅ 已保存'; showToast('子域名配置已保存'); }
                else throw new Error(data.error || '保存失败');
            } catch(e) { btn.textContent = '❌ 失败'; showToast('保存失败: ' + e.message); }
            setTimeout(function() { btn.textContent = orig; btn.disabled = false; }, 1500);
        }

        async function manualSubdomainUpdate(sub, btn) {
            if (btn) { btn.disabled = true; btn.textContent = '⏳ 调度中...'; }
            const resultDiv = document.getElementById('subdomainResult');
            if (resultDiv) { resultDiv.style.display = 'block'; resultDiv.style.background = 'rgba(16,185,129,0.08)'; resultDiv.innerHTML = '🤖 正在按运营商拉取优选节点并推送 DNS（约 15-40 秒）...'; }
            try {
                const res = await fetch('/api/subdomain-update', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sub: sub || null }) });
                const data = await res.json();
                if (resultDiv) {
                    if (data.success) {
                        const linesArr = (data.results || []).map(function(r) {
                            if (r.skipped) return '⏸️ ' + r.sub + ' 已停用';
                            if (r.success) return '✅ ' + r.sub + '（' + r.ispType + '）→ ' + r.topNodes.map(function(n){ return n.ip; }).join('、');
                            return '❌ ' + r.sub + '（' + r.ispType + '）: ' + r.error;
                        });
                        resultDiv.style.background = 'rgba(34,197,94,0.08)';
                        resultDiv.innerHTML = linesArr.join('<br>');
                    } else {
                        resultDiv.style.background = 'rgba(239,68,68,0.08)';
                        resultDiv.innerHTML = '❌ ' + (data.error || '调度失败');
                    }
                }
            } catch(e) {
                if (resultDiv) { resultDiv.style.background = 'rgba(239,68,68,0.08)'; resultDiv.innerHTML = '❌ ' + e.message; }
            }
            if (btn) { btn.disabled = false; btn.textContent = '单独调度'; }
        }

        // ==========================================
        // 🌟 新增：RTT 实时监测引擎 (每隔 3 秒探测一次)
        // ==========================================
        async function measureRTT() {
            const start = performance.now();
            try {
                // 加上时间戳强制绕过浏览器本地缓存
                await fetch('/__client_rtt__?t=' + Date.now(), { mode: 'no-cors', cache: 'no-store' });
                const rtt = Math.round(performance.now() - start);
                const rttEl = document.getElementById('rttValue');
                const dotEl = document.getElementById('rttDot');
                
                rttEl.textContent = rtt + ' ms';
                
                // 根据延迟改变呼吸灯颜色
                if (rtt < 80) {
                    dotEl.style.background = 'var(--success)'; dotEl.style.boxShadow = '0 0 8px var(--success)';
                    rttEl.style.color = 'var(--success)';
                } else if (rtt < 200) {
                    dotEl.style.background = 'var(--warning)'; dotEl.style.boxShadow = '0 0 8px var(--warning)';
                    rttEl.style.color = 'var(--warning)';
                } else {
                    dotEl.style.background = 'var(--danger)'; dotEl.style.boxShadow = '0 0 8px var(--danger)';
                    rttEl.style.color = 'var(--danger)';
                }
            } catch (e) {
                document.getElementById('rttValue').textContent = '断连';
                document.getElementById('rttDot').style.background = 'var(--danger)';
            }
        }
        
        // 先立即执行一次，然后每 3 秒循环探测
        measureRTT();
        setInterval(measureRTT, 3000);

    // 🚀 新增：前端探针自动检测脚本
        async function fetchCfTrace() {
            try {
                const res = await fetch('/api/trace');
                const data = await res.json();
                if (data.success) {
                    // 拼接访客入口信息：国家 城市 (机房代码)
                    let entryText = data.entryCountry;
                    if (data.entryCity && data.entryCity !== '未知') entryText += ' ' + data.entryCity;
                    entryText += ' (' + data.entryColo + ')';
                    
                    document.getElementById('trace-entry').innerText = entryText;
                    
                    // 落地机房处理
                    const egressText = data.egressColo;
                    const egressElem = document.getElementById('trace-egress');
                    egressElem.innerText = egressText;
                    
                    // 核心逻辑：如果入口和落地机房不一致，显示高亮提示（智能调度触发）
                    if (data.entryColo !== egressText && egressText !== '探测中...' && egressText !== '获取失败') {
                        egressElem.style.color = 'var(--warning)'; // 变成橘黄色警示
                        egressElem.innerText += ' (智能放置/回源)';
                    }
                }
            } catch(e) {
                document.getElementById('trace-entry').innerText = '获取超时';
                document.getElementById('trace-egress').innerText = '获取超时';
            }
        }
        
        // 当网页加载完成时，延迟0.5秒执行探针扫描（避免卡顿主页渲染）
        window.addEventListener('DOMContentLoaded', () => {
            setTimeout(fetchCfTrace, 500);
            loadBotConfig();
            loadFailoverConfig();
        });
    // 🚀 新增：全云厂商节点数据库 (包含 Cloudflare 支持的所有主要区域)
        var cfRegions = {
            aws: [
                { label: "🇭🇰 中国香港", value: "aws:ap-east-1" },
                { label: "🇯🇵 日本 (东京)", value: "aws:ap-northeast-1" },
                { label: "🇯🇵 日本 (大阪)", value: "aws:ap-northeast-3" },
                { label: "🇸🇬 新加坡", value: "aws:ap-southeast-1" },
                { label: "🇰🇷 韩国 (首尔)", value: "aws:ap-northeast-2" },
                { label: "🇺🇸 美国西部 (加州)", value: "aws:us-west-1" },
                { label: "🇺🇸 美国西部 (俄勒冈)", value: "aws:us-west-2" },
                { label: "🇺🇸 美国东部 (弗吉尼亚)", value: "aws:us-east-1" },
                { label: "🇦🇺 澳大利亚 (悉尼)", value: "aws:ap-southeast-2" },
                { label: "🇮🇳 印度 (孟买)", value: "aws:ap-south-1" },
                { label: "🇬🇧 英国 (伦敦)", value: "aws:eu-west-2" },
                { label: "🇩🇪 德国 (法兰克福)", value: "aws:eu-central-1" }
            ],
            gcp: [
                { label: "🇹🇼 中国台湾 (彰化)", value: "gcp:asia-east1" },
                { label: "🇭🇰 中国香港", value: "gcp:asia-east2" },
                { label: "🇯🇵 日本 (东京)", value: "gcp:asia-northeast1" },
                { label: "🇯🇵 日本 (大阪)", value: "gcp:asia-northeast2" },
                { label: "🇰🇷 韩国 (首尔)", value: "gcp:asia-northeast3" },
                { label: "🇸🇬 新加坡", value: "gcp:asia-southeast1" },
                { label: "🇺🇸 美国西部 (洛杉矶)", value: "gcp:us-west2" },
                { label: "🇺🇸 美国西部 (俄勒冈)", value: "gcp:us-west1" },
                { label: "🇺🇸 美国东部 (弗吉尼亚)", value: "gcp:us-east4" },
                { label: "🇦🇺 澳大利亚 (悉尼)", value: "gcp:australia-southeast1" },
                { label: "🇬🇧 英国 (伦敦)", value: "gcp:europe-west2" },
                { label: "🇩🇪 德国 (法兰克福)", value: "gcp:europe-west3" }
            ],
            azure: [
                { label: "🇭🇰 中国香港 (East Asia)", value: "azure:eastasia" },
                { label: "🇸🇬 新加坡 (Southeast Asia)", value: "azure:southeastasia" },
                { label: "🇯🇵 日本东部 (东京)", value: "azure:japaneast" },
                { label: "🇯🇵 日本西部 (大阪)", value: "azure:japanwest" },
                { label: "🇰🇷 韩国中部 (首尔)", value: "azure:koreacentral" },
                { label: "🇺🇸 美国西部 (West US)", value: "azure:westus" },
                { label: "🇺🇸 美国东部 (East US)", value: "azure:eastus" },
                { label: "🇬🇧 英国南部 (伦敦)", value: "azure:uksouth" },
                { label: "🇳🇱 西欧 (荷兰)", value: "azure:westeurope" }
            ]
        };

        // 🚀 新增：联动菜单处理逻辑
        function handleModeChange() {
            var mode = document.getElementById('cf-mode-select').value;
            var regionSelect = document.getElementById('cf-region-select');
            var customInput = document.getElementById('cf-custom-input');
            
            regionSelect.style.display = 'none';
            customInput.style.display = 'none';
            
            if (mode === 'aws' || mode === 'gcp' || mode === 'azure') {
                regionSelect.style.display = 'block';
                regionSelect.innerHTML = ''; 
                var regions = cfRegions[mode];
                regions.forEach(function(r) {
                    var opt = document.createElement('option');
                    opt.value = r.value;
                    opt.innerText = r.label;
                    regionSelect.appendChild(opt);
                });
            } else if (mode === 'custom') {
                customInput.style.display = 'block';
            }
        }

        // 🚀 新增：调用部署修改接口
        async function updatePlacement() {
            var statusElem = document.getElementById('place-status');
            var modeVal = document.getElementById('cf-mode-select').value;
            var placementPayload = {};
            
            if (modeVal === 'aws' || modeVal === 'gcp' || modeVal === 'azure') {
                var regionVal = document.getElementById('cf-region-select').value;
                placementPayload = { region: regionVal };
            } else if (modeVal === 'custom') {
                var customVal = document.getElementById('cf-custom-input').value;
                if (!customVal || customVal.trim() === '') {
                    statusElem.innerText = "❌ 请填写自定义区域代码（如 gcp:asia-east2）";
                    statusElem.style.color = "var(--danger)";
                    return;
                }
                placementPayload = { region: customVal.trim() };
            } else {
                placementPayload = JSON.parse(modeVal);
            }

            statusElem.innerText = "⏳ 正在提交请求，请稍候...";
            statusElem.style.color = "var(--warning)";
            
            try {
                var res = await fetch('/api/placement', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ placement: placementPayload })
                });
                var data = await res.json();
                if (data.success) {
                    statusElem.innerText = "✅ " + data.msg;
                    statusElem.style.color = "var(--success)";
                } else {
                    statusElem.innerText = "❌ " + data.msg;
                    statusElem.style.color = "var(--danger)";
                }
            } catch(e) {
                statusElem.innerText = "❌ 网络错误: " + e.message;
                statusElem.style.color = "var(--danger)";
            }
        }
    // 🚀 魔法功能：自动继承现有的模式选项 (增强稳定版)
        setTimeout(() => {
            const sourceSelect = document.getElementById('mode');
            const batchSelect = document.getElementById('batch-mode-select');
            if (sourceSelect && batchSelect) {
                batchSelect.innerHTML = sourceSelect.innerHTML;
            }
        }, 100); 

        // 🚀 全选 / 取消全选逻辑
        function toggleSelectAll(checkbox) {
            const checkboxes = document.querySelectorAll('.node-cb');
            checkboxes.forEach(cb => cb.checked = checkbox.checked);
        }

        // 🚀 并发批量修改模式逻辑 (终极多线程逐个击破版)
        async function batchUpdateModes() {
            const statusElem = document.getElementById('batch-status');
            const newMode = document.getElementById('batch-mode-select').value;
            
            const selectedPrefixes = Array.from(document.querySelectorAll('.node-cb:checked')).map(cb => cb.value);

            if (selectedPrefixes.length === 0) {
                statusElem.innerText = "⚠️ 请先打勾需要修改的节点！";
                statusElem.style.color = "var(--warning)";
                return;
            }

            if (!confirm("确定要将勾选的 " + selectedPrefixes.length + " 个节点切换为该模式吗？")) return;

            statusElem.innerText = "⏳ 正在多线程并发修改节点...";
            statusElem.style.color = "var(--primary)";

            try {
                // 1. 先获取当前所有的节点详细数据
                const getRes = await fetch('/api/routes');
                const allRoutes = await getRes.json();
                
                // 2. 筛选出你要修改的那些节点
                const nodesToUpdate = allRoutes.filter(r => selectedPrefixes.includes(r.prefix));

                // 3. 核心魔法：Promise.all 并发！瞬间发出多个独立的保存请求
                await Promise.all(nodesToUpdate.map(async (r) => {
                    const payload = Object.assign({}, r);
                    payload.oldPrefix = r.prefix; 
                    payload.mode = newMode; 
                    
                    const postRes = await fetch('/api/routes', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    
                    if (!postRes.ok) {
                        throw new Error("节点 " + r.prefix + " 保存失败");
                    }
                }));
                
                statusElem.innerText = "✅ 批量修改成功！";
                statusElem.style.color = "var(--success)";
                setTimeout(() => location.reload(), 1000); 

            } catch (e) {
                statusElem.innerText = "❌ 失败: " + e.message;
                statusElem.style.color = "var(--danger)";
            }
        }
    async function deployWorker() {
            const codeArea = document.getElementById('codeArea');
            const fileInput = document.getElementById('fileInput');
            let codeContent = codeArea.value;
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                codeContent = await file.text();
            }
            if (!codeContent.trim()) {
                alert('⚠️ 失败：请先粘贴代码，或者选择一个 .js 文件！');
                return;
            }
            if (!confirm('🚨 危险操作确认 🚨\\n\\n你即将强行覆盖当前 Worker 的代码。\\n如果新代码有错误，此面板将会瘫痪，只能去网页后台抢修！\\n\\n确定代码 100% 正确并覆盖吗？')) return;
            const btn = document.getElementById('deployBtn');
            const originalText = btn.innerText;
            btn.innerText = '⏳ 正在与 Cloudflare 通信并部署...';
            btn.disabled = true;
            btn.style.opacity = '0.7';
            try {
                const res = await fetch('/api/deploy', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ newCode: codeContent })
                });
                const data = await res.json();
                if (data.success) {
                    alert('🎉 成功！' + data.msg + '\\n\\n点击确定后页面将自动刷新。');
                    window.location.reload(); 
                } else {
                    alert('❌ 部署失败：\\n' + JSON.stringify(data.error));
                }
            } catch (e) {
                alert('🚨 异常：\\n' + e.message);
            } finally {
                btn.innerText = originalText;
                btn.disabled = false;
                btn.style.opacity = '1';
            }
        }
        // ==========================================
        // 🟢 在线更新模块
        // ==========================================
        // 使用顶部已定义的 CURRENT_VERSION 和 GITHUB_RAW_URL
        
        let latestCode = ""; 

        async function checkForUpdates() {
            try {
                const res = await fetch(GITHUB_RAW_URL + '?t=' + new Date().getTime());
                if (!res.ok) return;
                latestCode = await res.text();
                
                // 🚀 核心修复：加入双重反斜杠，防止正则在 Worker 中变成注释 (//) 导致崩溃
                const versionMatch = latestCode.match(/\\/\\/\\s*VERSION:\\s*v?([\\d\\.]+)/i);
                if (versionMatch && versionMatch[1]) {
                    const latestVersion = versionMatch[1];
                    if (latestVersion !== CURRENT_VERSION) {
                        document.getElementById('updateAlert').style.display = 'block';
                        document.getElementById('updateMsg').innerText = '当前版本: v' + CURRENT_VERSION + ' | 发现最新版本: v' + latestVersion + ' (Github)';
                    }
                }
            } catch (e) {
                console.log("检测更新失败:", e);
            }
        }

        async function doOnlineUpdate() {
            if (!confirm('🚀 确定要从 GitHub 拉取最新版本并覆盖当前节点吗？\\n\\n（这将会保留你的所有环境变量和数据库绑定）')) return;
            
            const btn = document.getElementById('onlineUpdateBtn');
            btn.innerText = '⏳ 正在拉取并部署...';
            btn.disabled = true;
            btn.style.opacity = '0.7';

            try {
                // 直接复用我们之前写好的防丢数据库高级 API
                const res = await fetch('/api/deploy', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ newCode: latestCode })
                });
                const data = await res.json();
                if (data.success) {
                    alert('🎉 在线更新成功！\\n\\n点击确定后页面将自动刷新，畅享新版本！');
                    window.location.reload(); 
                } else {
                    alert('❌ 更新失败：\\n' + JSON.stringify(data.error));
                }
            } catch (e) {
                alert('🚨 异常：\\n' + e.message);
            } finally {
                btn.innerText = '🚀 一键拉取并升级';
                btn.disabled = false;
                btn.style.opacity = '1';
            }
        }

    </script>
</body>
</html>
`;

// ==========================================
// 2. 后端 Worker 主逻辑处理区 (核心故障转移 + TG Bot播报 + 智能流量拉取)
// ==========================================

// 用于向 Cloudflare 获取对应时间段的总流量 (支持北京时间今日、近7天、近30天)
async function getCFTraffic(env, type) {
    if (!env.CF_API_TOKEN || !env.CF_ZONE_ID) return "缺少变量";
    try {
        const end = new Date();
        let graphqlQuery = {};

        if (type === 'today') {
            // 【今日流量】查询：从北京时间今日 00:00 算起，使用 AdaptiveGroups
            // 1. 获取北京时间并清零时分秒
            const beijingTime = new Date(end.getTime() + 8 * 3600000);
            beijingTime.setUTCHours(0, 0, 0, 0);
            // 2. 转回 UTC 供 API 查询
            const start = new Date(beijingTime.getTime() - 8 * 3600000);
            
            graphqlQuery = {
                query: `
                query {
                  viewer {
                    zones(filter: {zoneTag: "${env.CF_ZONE_ID}"}) {
                      httpRequestsAdaptiveGroups(
                        limit: 1,
                        filter: {
                          datetime_geq: "${start.toISOString()}",
                          datetime_leq: "${end.toISOString()}"
                        }
                      ) {
                        sum {
                          edgeResponseBytes
                        }
                      }
                    }
                  }
                }`
            };
        } else {
            // 【7天、30天】查询：传入数字代表天数，使用 1dGroups
            const start = new Date(end.getTime() - type * 24 * 3600000);
            const dateGeq = start.toISOString().split('T')[0];
            const dateLeq = end.toISOString().split('T')[0];
            graphqlQuery = {
                query: `
                query {
                  viewer {
                    zones(filter: {zoneTag: "${env.CF_ZONE_ID}"}) {
                      httpRequests1dGroups(
                        limit: 10000,
                        filter: {
                          date_geq: "${dateGeq}",
                          date_leq: "${dateLeq}"
                        }
                      ) {
                        sum {
                          bytes
                        }
                      }
                    }
                  }
                }`
            };
        }

        const cfRes = await fetch('https://api.cloudflare.com/client/v4/graphql', {
            method: 'POST',
            headers: { 
                'Authorization': `Bearer ${env.CF_API_TOKEN}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(graphqlQuery)
        });
        
        const cfData = await cfRes.json();
        
        if (cfData.errors && cfData.errors.length > 0) {
            return `API报错: ${cfData.errors[0].message}`;
        }
        
        const zones = cfData?.data?.viewer?.zones;
        let totalBytes = 0;

        if (zones && zones.length > 0) {
            if (type === 'today' && zones[0].httpRequestsAdaptiveGroups) {
                totalBytes = zones[0].httpRequestsAdaptiveGroups[0]?.sum?.edgeResponseBytes || 0;
            } else if (type !== 'today' && zones[0].httpRequests1dGroups) {
                // 将多天的 bytes 聚合累加
                zones[0].httpRequests1dGroups.forEach(g => { totalBytes += (g.sum.bytes || 0); });
            }
        }

        if (totalBytes === 0) return "0 B";
        if (totalBytes >= 1099511627776) return (totalBytes / 1099511627776).toFixed(2) + " TB";
        if (totalBytes >= 1073741824) return (totalBytes / 1073741824).toFixed(2) + " GB";
        if (totalBytes >= 1048576) return (totalBytes / 1048576).toFixed(2) + " MB";
        if (totalBytes >= 1024) return (totalBytes / 1024).toFixed(2) + " KB";
        return totalBytes + " B";

    } catch(e) {
        return "请求异常";
    }
}

// 字节数 -> 人类可读格式（TB/GB/MB/KB/B）
function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return "0 B";
    if (bytes >= 1099511627776) return (bytes / 1099511627776).toFixed(2) + " TB";
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + " GB";
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + " MB";
    if (bytes >= 1024) return (bytes / 1024).toFixed(2) + " KB";
    return bytes + " B";
}

// 向 Cloudflare GraphQL 查询单个节点「北京时间今日」的精准流量字节数
async function getRouteTodayBytes(env, prefix) {
    if (!env.CF_API_TOKEN || !env.CF_ZONE_ID) return 0;
    try {
        const end = new Date();
        const beijingTime = new Date(end.getTime() + 8 * 3600000);
        beijingTime.setUTCHours(0, 0, 0, 0);
        const start = new Date(beijingTime.getTime() - 8 * 3600000);

        const graphqlQuery = {
            query: `query {
              viewer {
                zones(filter: {zoneTag: "${env.CF_ZONE_ID}"}) {
                  httpRequestsAdaptiveGroups(
                    limit: 1,
                    filter: {
                      clientRequestPath_like: "/${prefix}%",
                      datetime_geq: "${start.toISOString()}",
                      datetime_leq: "${end.toISOString()}"
                    }
                  ) {
                    sum { edgeResponseBytes }
                  }
                }
              }
            }`
        };

        const cfRes = await fetch('https://api.cloudflare.com/client/v4/graphql', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(graphqlQuery)
        });
        const cfData = await cfRes.json();
        if (cfData.errors && cfData.errors.length > 0) return 0;
        const zones = cfData?.data?.viewer?.zones;
        if (zones && zones.length > 0 && zones[0].httpRequestsAdaptiveGroups) {
            return zones[0].httpRequestsAdaptiveGroups[0]?.sum?.edgeResponseBytes || 0;
        }
        return 0;
    } catch (e) {
        return 0;
    }
}

// 后台刷新节点的今日流量缓存（仅刷新缺失/过期>5分钟的节点，避免频繁打爆 CF GraphQL）
async function refreshRouteBandwidth(env, prefixes, todayStr) {
    if (!env.CF_API_TOKEN || !env.CF_ZONE_ID || !prefixes || prefixes.length === 0) return;
    try {
        const cached = await env.DB.prepare(`SELECT prefix, updated_at FROM route_bandwidth WHERE date = ?`).bind(todayStr).all();
        const cachedMap = new Map((cached.results || []).map(r => [r.prefix, r.updated_at]));
        const now = Date.now();
        const stalePrefixes = prefixes.filter(p => {
            const u = cachedMap.get(p);
            if (!u) return true;
            const t = new Date(String(u).replace(' ', 'T') + 'Z').getTime();
            return isNaN(t) || (now - t) > 5 * 60 * 1000;
        });
        if (stalePrefixes.length === 0) return;
        await Promise.all(stalePrefixes.map(async (prefix) => {
            const bytes = await getRouteTodayBytes(env, prefix);
            try {
                await env.DB.prepare(`INSERT INTO route_bandwidth (prefix, date, bytes, updated_at) VALUES (?, ?, ?, datetime('now')) ON CONFLICT(prefix, date) DO UPDATE SET bytes = ?, updated_at = datetime('now')`)
                    .bind(prefix, todayStr, bytes, bytes).run();
            } catch (e) {}
        }));
    } catch (e) {}
}

// 用于生成 TG 播报消息的核心工具函数 (单面板 + 流量之王统计版)
async function sendTgStats(env, chatId) {
    try {
        // 检查Bot推送开关
        try {
            const botCfg = await env.DB.prepare('SELECT bot_enabled FROM bot_config WHERE id = 1').first();
            if (botCfg && !botCfg.bot_enabled) {
                console.log('Bot通知已关闭，跳过发送');
                return;
            }
        } catch(e) {}
        
        const totalQuery = await env.DB.prepare(`SELECT COUNT(*) as count FROM visitor_logs WHERE date(timestamp, '+8 hours') = date('now', '+8 hours')`).first();
        const topRegionQuery = await env.DB.prepare(`SELECT country, COUNT(*) as c FROM visitor_logs WHERE date(timestamp, '+8 hours') = date('now', '+8 hours') GROUP BY country ORDER BY c DESC LIMIT 1`).first();
        const topNodeQuery = await env.DB.prepare(`
            SELECT r.remark, COUNT(v.id) as c 
            FROM visitor_logs v 
            LEFT JOIN routes r ON v.prefix = r.prefix 
            WHERE date(v.timestamp, '+8 hours') = date('now', '+8 hours') 
            GROUP BY v.prefix 
            ORDER BY c DESC LIMIT 1
        `).first();

        // 获取多时间维度流量
        const [trafficToday, traffic7d, traffic30d] = await Promise.all([
            getCFTraffic(env, 'today'),
            getCFTraffic(env, 7),
            getCFTraffic(env, 30)
        ]);

        // ================= 新增：获取今日流量消耗 TOP 1 节点 =================
        let topNodeMsg = "暂无数据";
        if (env.CF_API_TOKEN && env.CF_ZONE_ID && env.DB) {
            try {
                // 1. 获取所有节点
                const { results: routes } = await env.DB.prepare(`SELECT prefix, remark FROM routes`).all();
                if (routes && routes.length > 0) {
                    const end = new Date();
                    const beijingTime = new Date(end.getTime() + 8 * 3600000);
                    beijingTime.setUTCHours(0, 0, 0, 0);
                    const start = new Date(beijingTime.getTime() - 8 * 3600000);

                    let maxBytes = 0;
                    let topNodeName = "无";

                    // 2. 并发向 CF 查询每个节点今天的精准流量
                    await Promise.all(routes.map(async (r) => {
                        try {
                            const graphqlQuery = {
                                query: `query {
                                  viewer {
                                    zones(filter: {zoneTag: "${env.CF_ZONE_ID}"}) {
                                      httpRequestsAdaptiveGroups(
                                        limit: 1,
                                        filter: {
                                          clientRequestPath_like: "/${r.prefix}%",
                                          datetime_geq: "${start.toISOString()}",
                                          datetime_leq: "${end.toISOString()}"
                                        }
                                      ) {
                                        sum { edgeResponseBytes }
                                      }
                                    }
                                  }
                                }`
                            };

                            const cfRes = await fetch('https://api.cloudflare.com/client/v4/graphql', {
                                method: 'POST',
                                headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
                                body: JSON.stringify(graphqlQuery)
                            });
                            
                            const cfData = await cfRes.json();
                            const bytes = cfData?.data?.viewer?.zones?.[0]?.httpRequestsAdaptiveGroups?.[0]?.sum?.edgeResponseBytes || 0;
                            
                            // 3. 找出最大值
                            if (bytes > maxBytes) {
                                maxBytes = bytes;
                                topNodeName = r.remark || r.prefix;
                            }
                        } catch(e) {}
                    }));

                    // 4. 转换字节并组装文本
                    if (maxBytes > 0) {
                        let formatted = "0 B";
                        if (maxBytes >= 1099511627776) formatted = (maxBytes / 1099511627776).toFixed(2) + " TB";
                        else if (maxBytes >= 1073741824) formatted = (maxBytes / 1073741824).toFixed(2) + " GB";
                        else if (maxBytes >= 1048576) formatted = (maxBytes / 1048576).toFixed(2) + " MB";
                        else if (maxBytes >= 1024) formatted = (maxBytes / 1024).toFixed(2) + " KB";
                        else formatted = maxBytes + " B";
                        
                        topNodeMsg = `${topNodeName} 跑了 ${formatted}`;
                    } else {
                        topNodeMsg = "今日全站零消耗";
                    }
                }
            } catch (e) {
                topNodeMsg = "获取失败";
            }
        }
        // ====================================================================

        const totalStr = totalQuery ? totalQuery.count : 0;
        const regionStr = topRegionQuery ? `${topRegionQuery.country === 'CN' ? '🇨🇳 中国大陆' : topRegionQuery.country} (${topRegionQuery.c} 次)` : '暂无记录';
        const nodeStr = topNodeQuery ? `${topNodeQuery.remark || '未命名节点'} (${topNodeQuery.c} 次)` : '暂无记录';

        const msg = 
            `📊 *今日反代播放数据*\n\n` +
            `▶️ *今日总播放次数:* ${totalStr} 次\n` +
            `🌍 *最多访问地区:* ${regionStr}\n` +
            `🚀 *最喜欢的EMBY:* ${nodeStr}\n\n` +
            `🌐 *实际流量消耗:*\n` +
            `当天内: ${trafficToday}\n` +
            `七天内: ${traffic7d}\n` +
            `30天内: ${traffic30d}\n\n` +
            `🏆 *今日流量之王:*\n` +
            `👑 ${topNodeMsg}`;

        await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, text: msg, parse_mode: 'Markdown' })
        });
    } catch (e) {
        console.error("TG Send Error:", e);
    }
}


// ==========================================
// 3. 智能DNS自动更新引擎
// ==========================================

// 智能评分函数：多维度评估节点质量
function calculateNodeScore(latency, isIPv6, isDomain, history) {
    let score = 100;

    // 延迟评分（权重40%）：移动宽带延迟阈值适当放宽
    const latencyThresholds = {
        excellent: 200,  // <200ms 极佳
        good: 400,       // <400ms 正常
        acceptable: 800  // <800ms 可用
    };

    if (latency < latencyThresholds.excellent) {
        score += 40;
    } else if (latency < latencyThresholds.good) {
        score += 30 - ((latency - latencyThresholds.excellent) / (latencyThresholds.good - latencyThresholds.excellent)) * 10;
    } else if (latency < latencyThresholds.acceptable) {
        score += 15 - ((latency - latencyThresholds.good) / (latencyThresholds.acceptable - latencyThresholds.good)) * 15;
    } else {
        score -= 20; // 超时节点扣分
    }

    // 稳定性评分（权重30%）：基于历史成功率
    if (history) {
        const successRate = history.successCount / Math.max(history.totalCount, 1);
        score += successRate * 30;

        // 历史平均延迟加分
        if (history.avgLatency && history.avgLatency < 300) {
            score += 10;
        }
    }

    // IPv6 加分（权重10%）：IPv6通常更稳定
    if (isIPv6) score += 10;

    // 域名优选加分（权重10%）：CNAME通常更稳定
    if (isDomain) score += 10;

    return Math.round(score);
}

// 多样性选择算法：确保选择的节点类型多样化
function selectDiverseNodes(sortedNodes, count) {
    if (sortedNodes.length <= count) return sortedNodes;

    const selected = [];
    const types = { ipv4: null, ipv6: null, domain: null };

    // 第一轮：每种类型选最优的
    for (const node of sortedNodes) {
        if (selected.length >= count) break;
        let type = 'ipv4';
        if (node.isIPv6) type = 'ipv6';
        else if (node.isDomain) type = 'domain';

        if (!types[type]) {
            types[type] = node;
            selected.push(node);
        }
    }

    // 第二轮：按评分补满
    for (const node of sortedNodes) {
        if (selected.length >= count) break;
        if (!selected.includes(node)) {
            selected.push(node);
        }
    }

    return selected;
}

// 通用：确保智能DNS相关表存在（含子域名调度表）
async function ensureDnsTables(env) {
    if (!env.DB) return;
    try {
        await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_update_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nodes_json TEXT DEFAULT '[]',
            trigger_type TEXT DEFAULT 'auto',
            total_tested INTEGER DEFAULT 0,
            success_count INTEGER DEFAULT 0,
            error_msg TEXT DEFAULT '',
            sub TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_node_history (
            node_ip TEXT PRIMARY KEY,
            total_count INTEGER DEFAULT 0,
            success_count INTEGER DEFAULT 0,
            avg_latency INTEGER DEFAULT 0,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_auto_config (
            id INTEGER PRIMARY KEY DEFAULT 1,
            isp_type TEXT DEFAULT '移动',
            top_n INTEGER DEFAULT 3,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_subdomain_config (
            sub TEXT PRIMARY KEY,
            isp_type TEXT DEFAULT '移动',
            top_n INTEGER DEFAULT 3,
            enabled INTEGER DEFAULT 1,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        await env.DB.prepare(`INSERT OR IGNORE INTO dns_auto_config (id, isp_type, top_n) VALUES (1, '移动', 3)`).run();
        await env.DB.prepare(`INSERT OR IGNORE INTO dns_subdomain_config (sub, isp_type, top_n, enabled) VALUES ('yd', '移动', 3, 1)`).run();
        await env.DB.prepare(`INSERT OR IGNORE INTO dns_subdomain_config (sub, isp_type, top_n, enabled) VALUES ('lt', '联通', 3, 1)`).run();
        await env.DB.prepare(`INSERT OR IGNORE INTO dns_subdomain_config (sub, isp_type, top_n, enabled) VALUES ('dx', '电信', 3, 1)`).run();
        // 兼容旧表：补充 sub 列
        try { await env.DB.exec(`ALTER TABLE dns_update_history ADD COLUMN sub TEXT DEFAULT ''`); } catch(e) {}
    } catch(e) { console.error("ensureDnsTables:", e.message); }
}

// 根据 Cloudflare 客户端信息判断运营商（移动/联通/电信）
function detectISPFromCF(cf) {
    if (!cf) return null;
    const org = (cf.asOrganization || '').toLowerCase();
    const asn = cf.asn || 0;
    const mobileAsn = [56040,24400,56041,56046,56042,56043,56044,56045,56047,56048,24547,56020,56021,56022,24400];
    const unicomAsn  = [4837,9929,10099,17621,136952,45062,23848,17622,17623];
    const telecomAsn = [4134,4809,4812,140504,140503,23724,136948,136149];
    if (org.includes('mobile') || org.includes('移动') || mobileAsn.includes(asn)) return '移动';
    if (org.includes('unicom') || org.includes('联通') || unicomAsn.includes(asn)) return '联通';
    if (org.includes('telecom') || org.includes('电信') || telecomAsn.includes(asn)) return '电信';
    return null;
}

// 自动DNS更新核心函数（参数化：可针对任意域名+运营商）
async function runISPDnsUpdate(env, opts) {
    const domain = opts.domain;
    const ispType = opts.ispType || '移动';
    const topN = opts.topN || 3;
    const triggerType = opts.triggerType || 'auto';
    if (!env.DB || !env.CF_API_TOKEN || !env.CF_ZONE_ID || !domain) {
        return { success: false, error: '缺少必要的环境变量', domain };
    }
    try {
        // 1. 根据 ispType 获取节点
        const reqType = ispType.toLowerCase();
        const candidates = [];
        if (['all', '电信', '联通', '移动', '多线', 'ipv6'].includes(reqType)) {
            try {
                const res1 = await fetch('https://api.uouin.com/cloudflare.html', { headers: { 'User-Agent': 'Mozilla/5.0' } });
                if (res1.ok) {
                    const text1 = await res1.text();
                    const cleanText = text1.replace(/<[^>]+>/g, ' ');
                    const regex = /(电信|联通|移动|多线|ipv6)\s+((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)|(?:[a-fA-F0-9]{1,4}:)+[a-fA-F0-9]{1,4})/gi;
                    let match;
                    while ((match = regex.exec(cleanText)) !== null) {
                        const lineType = match[1].toLowerCase();
                        let ip = match[2];
                        if (ip.includes(':') && !ip.startsWith('[')) ip = '[' + ip + ']';
                        if (reqType === 'all' || reqType === lineType) candidates.push(ip);
                    }
                }
            } catch(e) {}
        }
        if (['all', '优选'].includes(reqType)) {
            try {
                const res2 = await fetch('https://raw.githubusercontent.com/ZhiXuanWang/cf-speed-dns/refs/heads/main/ipTop10.html', { headers: { 'User-Agent': 'Mozilla/5.0' } });
                if (res2.ok) {
                    const text2 = await res2.text();
                    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
                    const matched = text2.match(ipv4Regex) || [];
                    matched.forEach(ip => {
                        if (!ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.')) candidates.push(ip);
                    });
                }
            } catch(e) {}
        }
        const uniqueIPs = [...new Set(candidates)];
        for (let i = uniqueIPs.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [uniqueIPs[i], uniqueIPs[j]] = [uniqueIPs[j], uniqueIPs[i]];
        }
        const testIPs = uniqueIPs.slice(0, 15);
        if (testIPs.length === 0) throw new Error('未获取到' + ispType + '节点');

        // 2. 并发测速
        const pingResults = await Promise.all(testIPs.map(async (ip) => {
            const cleanIp = ip.replace(/[\[\]]/g, '');
            const isIPv6 = ip.includes(':');
            const isDomain = /[a-zA-Z]/.test(cleanIp) && !isIPv6;
            let history = null;
            try {
                const histRow = await env.DB.prepare('SELECT success_count, total_count, avg_latency FROM dns_node_history WHERE node_ip = ?').bind(cleanIp).first();
                if (histRow) history = { successCount: histRow.success_count||0, totalCount: histRow.total_count||0, avgLatency: histRow.avg_latency||0 };
            } catch(e) {}
            const start = Date.now();
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 3000);
                await fetch(`https://${ip}/cdn-cgi/trace`, { mode: 'no-cors', signal: controller.signal });
                clearTimeout(timeoutId);
                let latency = Date.now() - start;
                if (latency > 3000) throw new Error('timeout');
                if (!isIPv6 && !isDomain) {
                    if (latency >= 500) latency = latency - 400;
                    else { const base = 40 + (latency/500)*60; latency = Math.floor(base) + Math.floor(Math.random()*10); }
                }
                const score = calculateNodeScore(latency, isIPv6, isDomain, history);
                return { ip, latency, score, isIPv6, isDomain, success: true };
            } catch(e) { return { ip, latency: 9999, score: 0, isIPv6, isDomain, success: false }; }
        }));

        const successNodes = pingResults.filter(r => r.success && r.latency < 2000);
        successNodes.sort((a, b) => b.score - a.score);
        const topNodes = selectDiverseNodes(successNodes, topN);
        if (topNodes.length === 0) throw new Error('没有可用节点');

        // 3. 更新DNS（针对 domain）；子域与主域一致：推送到灰云真实 Cloudflare IP，
        //    由 *.erebus.de5.net/* 路由触发 Worker 反代，且 DNS 中的优选 IP 让客户端直连最优边缘
        const getRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records?name=${domain}`, { headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` } });
        const getData = await getRes.json();
        if (getData.success) {
            const records = getData.result.filter(r => r.type === 'A' || r.type === 'AAAA' || r.type === 'CNAME');
            for (const record of records) {
                await fetch(`https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records/${record.id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` } });
            }
        }
        for (const node of topNodes) {
            const cleanItem = node.ip.replace(/[\[\]]/g, '');
            let recordType = 'A';
            if (cleanItem.includes(':')) recordType = 'AAAA';
            else if (/[a-zA-Z]/.test(cleanItem)) recordType = 'CNAME';
            await fetch(`https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records`, { method: 'POST', headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ type: recordType, name: domain, content: cleanItem, ttl: 60, proxied: false }) });
        }

        const nowBeijing = new Date(Date.now() + 8*3600000).toISOString().replace('T',' ').split('.')[0];
        await env.DB.prepare(`INSERT INTO dns_update_history (nodes_json, trigger_type, total_tested, success_count, sub, created_at) VALUES (?, ?, ?, ?, ?, ?)`).bind(JSON.stringify(topNodes.map(n=>({ip:n.ip,latency:n.latency,score:n.score}))), triggerType, testIPs.length, successNodes.length, (opts.sub||''), nowBeijing).run();

        for (const node of pingResults) {
            const cleanIp = node.ip.replace(/[\[\]]/g, '');
            try {
                const existing = await env.DB.prepare('SELECT * FROM dns_node_history WHERE node_ip = ?').bind(cleanIp).first();
                if (existing) {
                    const newTotal = (existing.total_count||0)+1;
                    const newSuccess = (existing.success_count||0)+(node.success?1:0);
                    const newAvg = node.success ? ((existing.avg_latency||0)*(existing.total_count||0)+node.latency)/newTotal : existing.avg_latency||0;
                    await env.DB.prepare('UPDATE dns_node_history SET total_count=?, success_count=?, avg_latency=?, last_seen=? WHERE node_ip=?').bind(newTotal,newSuccess,Math.round(newAvg),nowBeijing,cleanIp).run();
                } else {
                    await env.DB.prepare('INSERT INTO dns_node_history (node_ip, total_count, success_count, avg_latency, last_seen) VALUES (?,?,?,?,?)').bind(cleanIp,1,node.success?1:0,node.success?node.latency:0,nowBeijing).run();
                }
            } catch(e) {}
        }

        const dnsPart = `已推送TOP${topNodes.length}到 ${domain}（灰云优选IP，由 *.erebus.de5.net/* 路由触发 Worker 反代）`;
        return { success: true, domain, ispType, message: `自动更新成功：【${ispType}】测试${testIPs.length}个节点，${successNodes.length}个可用，${dnsPart}`, topNodes: topNodes.map(n=>({ip:n.ip,latency:n.latency,score:n.score})), stats: { tested: testIPs.length, available: successNodes.length } };
    } catch(e) {
        try {
            const nowBeijing = new Date(Date.now() + 8*3600000).toISOString().replace('T',' ').split('.')[0];
            await env.DB.prepare(`INSERT INTO dns_update_history (nodes_json, trigger_type, total_tested, success_count, error_msg, sub, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind('[]', triggerType, 0, 0, e.message, (opts.sub||''), nowBeijing).run();
        } catch(e2) {}
        return { success: false, error: e.message, domain, ispType };
    }
}

// 自动更新所有已启用的子域名（yd/lt/dx 各自按运营商调度）
async function autoUpdateAllSubdomains(env) {
    if (!env.DB) return { success: false, error: '未绑定数据库' };
    await ensureDnsTables(env);
    let rows = [];
    try { rows = (await env.DB.prepare('SELECT sub, isp_type, top_n, enabled FROM dns_subdomain_config ORDER BY sub').all()).results || []; } catch(e) {}
    const results = [];
    // 每个子域单独发起一次 Worker 自调用，避免单次调用子请求数超过免费账户 50 上限
    // （dx+lt+yd 累加约 69 子请求，单次调用会撞墙；自调用让每个子域独占 50 预算）
    const baseUrl = 'https://' + (env.CF_DOMAIN || 'fandai.erebus.de5.net');
    for (const r of rows) {
        if (!r.enabled) { results.push({ sub: r.sub, enabled: false, skipped: true }); continue; }
        try {
            const resp = await fetch(baseUrl + '/api/subdomain-update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Cookie': 'admin_token=' + (env.ADMIN_TOKEN || '') },
                body: JSON.stringify({ sub: r.sub })
            });
            let j = {};
            try { j = await resp.json(); } catch(e2) {}
            if (Array.isArray(j.results) && j.results[0]) { j.results[0].sub = r.sub; results.push(j.results[0]); }
            else { results.push(Object.assign({ sub: r.sub }, j)); }
        } catch(e) {
            results.push({ sub: r.sub, success: false, error: e.message });
        }
    }
    return { success: true, results };
}

// 自动DNS更新核心函数（opts 可选；用于子域时传 {domain, sub} 以跳过DNS推送）
async function autoUpdateDNS(env, opts = {}) {
    if (!env.DB || !env.CF_API_TOKEN || !env.CF_ZONE_ID || !env.CF_DOMAIN) {
        return { success: false, error: '缺少必要的环境变量' };
    }
    const domain = opts.domain || env.CF_DOMAIN;
    
    // 先确保数据库表初始化
    try {
        // 智能DNS表初始化
        await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_update_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nodes_json TEXT DEFAULT '[]',
            trigger_type TEXT DEFAULT 'auto',
            total_tested INTEGER DEFAULT 0,
            success_count INTEGER DEFAULT 0,
            error_msg TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_node_history (
            node_ip TEXT PRIMARY KEY,
            total_count INTEGER DEFAULT 0,
            success_count INTEGER DEFAULT 0,
            avg_latency INTEGER DEFAULT 0,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        // 自动DNS配置表
        await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_auto_config (
            id INTEGER PRIMARY KEY DEFAULT 1,
            isp_type TEXT DEFAULT '移动',
            top_n INTEGER DEFAULT 3,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        // 插入默认配置
        try {
            await env.DB.prepare(`INSERT OR IGNORE INTO dns_auto_config (id, isp_type, top_n) VALUES (1, '移动', 3)`).run();
        } catch(e) {}
    } catch(e) {
        console.error("DB init in autoUpdateDNS:", e.message);
    }

    try {
        // 0. 读取自动DNS配置
        let config = { isp_type: '移动', top_n: 3 };
        try {
            const cfgRow = await env.DB.prepare('SELECT isp_type, top_n FROM dns_auto_config WHERE id = 1').first();
            if (cfgRow) {
                config.isp_type = cfgRow.isp_type || '移动';
                config.top_n = cfgRow.top_n || 3;
            }
        } catch(e) {}

        // 1. 根据配置获取节点 - 与 /api/get-remote-ips 使用完全一致的逻辑
        const reqType = config.isp_type.toLowerCase();
        const candidates = [];

        if (['all', '电信', '联通', '移动', '多线', 'ipv6'].includes(reqType)) {
            try {
                const res1 = await fetch('https://api.uouin.com/cloudflare.html', { headers: { 'User-Agent': 'Mozilla/5.0' } });
                if (res1.ok) {
                    const text1 = await res1.text();
                    const cleanText = text1.replace(/<[^>]+>/g, ' ');
                    const regex = /(电信|联通|移动|多线|ipv6)\s+((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)|(?:[a-fA-F0-9]{1,4}:)+[a-fA-F0-9]{1,4})/gi;
                    let match;
                    while ((match = regex.exec(cleanText)) !== null) {
                        const lineType = match[1].toLowerCase();
                        let ip = match[2];
                        if (ip.includes(':') && !ip.startsWith('[')) ip = '[' + ip + ']';
                        if (reqType === 'all' || reqType === lineType) candidates.push(ip);
                    }
                }
            } catch(e) {}
        }

        if (['all', '优选'].includes(reqType)) {
            try {
                const res2 = await fetch('https://raw.githubusercontent.com/ZhiXuanWang/cf-speed-dns/refs/heads/main/ipTop10.html', { headers: { 'User-Agent': 'Mozilla/5.0' } });
                if (res2.ok) {
                    const text2 = await res2.text();
                    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
                    const matched = text2.match(ipv4Regex) || [];
                    matched.forEach(ip => {
                        if (!ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.')) candidates.push(ip);
                    });
                }
            } catch(e) {}
        }

        // 去重并随机打乱，取前15个测速
        const uniqueIPs = [...new Set(candidates)];
        for (let i = uniqueIPs.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [uniqueIPs[i], uniqueIPs[j]] = [uniqueIPs[j], uniqueIPs[i]];
        }
        const testIPs = uniqueIPs.slice(0, 15);

        if (testIPs.length === 0) throw new Error('未获取到' + config.isp_type + '节点');

        // 2. 并发测速
        const pingResults = await Promise.all(testIPs.map(async (ip) => {
            const cleanIp = ip.replace(/[\[\]]/g, '');
            const isIPv6 = ip.includes(':');
            const isDomain = /[a-zA-Z]/.test(cleanIp) && !isIPv6;

            // 获取历史数据
            let history = null;
            try {
                const histRow = await env.DB.prepare(
                    'SELECT success_count, total_count, avg_latency FROM dns_node_history WHERE node_ip = ?'
                ).bind(cleanIp).first();
                if (histRow) {
                    history = {
                        successCount: histRow.success_count || 0,
                        totalCount: histRow.total_count || 0,
                        avgLatency: histRow.avg_latency || 0
                    };
                }
            } catch(e) {}

            const start = Date.now();
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 3000);
                await fetch(`https://${ip}/cdn-cgi/trace`, { mode: 'no-cors', signal: controller.signal });
                clearTimeout(timeoutId);

                let latency = Date.now() - start;
                if (latency > 3000) throw new Error('timeout');

                // IPv4延迟修正
                if (!isIPv6 && !isDomain) {
                    if (latency >= 500) latency = latency - 400;
                    else {
                        const base = 40 + (latency / 500) * 60;
                        latency = Math.floor(base) + Math.floor(Math.random() * 10);
                    }
                }

                const score = calculateNodeScore(latency, isIPv6, isDomain, history);

                return { ip, latency, score, isIPv6, isDomain, success: true };
            } catch(e) {
                return { ip, latency: 9999, score: 0, isIPv6, isDomain, success: false };
            }
        }));

        // 3. 筛选成功节点并按评分排序
        const successNodes = pingResults.filter(r => r.success && r.latency < 2000);
        successNodes.sort((a, b) => b.score - a.score);

        // 4. 多样性选择：确保TOP中尽量包含不同类型节点
        const topNodes = selectDiverseNodes(successNodes, config.top_n || 3);

        if (topNodes.length === 0) throw new Error('没有可用节点');

        // 5. 更新DNS（子域模式跳过：子域为橙云，A 记录 content 被 CF 忽略；
        //    优选 IP 改由 /api/best-ips 下发，供客户端本地 hosts/智能DNS 覆盖提速）
        if (!opts.sub) {
        // 删除旧DNS记录
        const getRes = await fetch(
            `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records?name=${domain}`,
            { headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` } }
        );
        const getData = await getRes.json();
        if (getData.success) {
            const records = getData.result.filter(r => r.type === 'A' || r.type === 'AAAA' || r.type === 'CNAME');
            for (const record of records) {
                await fetch(
                    `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records/${record.id}`,
                    { method: 'DELETE', headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` } }
                );
            }
        }

        // 添加新DNS记录
        for (const node of topNodes) {
            const cleanItem = node.ip.replace(/[\[\]]/g, '');
            let recordType = 'A';
            if (cleanItem.includes(':')) recordType = 'AAAA';
            else if (/[a-zA-Z]/.test(cleanItem)) recordType = 'CNAME';

            await fetch(
                `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records`,
                {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: recordType, name: domain, content: cleanItem, ttl: 60, proxied: true })
                }
            );
        }
        }

        // 6. 记录历史
        const nowBeijing = new Date(Date.now() + 8 * 3600000).toISOString().replace('T', ' ').split('.')[0];
        await env.DB.prepare(
            `INSERT INTO dns_update_history (nodes_json, trigger_type, total_tested, success_count, created_at, sub) VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(
            JSON.stringify(topNodes.map(n => ({ ip: n.ip, latency: n.latency, score: n.score }))),
            'auto',
            testIPs.length,
            successNodes.length,
            nowBeijing,
            opts.sub || ''
        ).run();

        // 7. 更新节点历史统计
        for (const node of pingResults) {
            const cleanIp = node.ip.replace(/[\[\]]/g, '');
            try {
                const existing = await env.DB.prepare(
                    'SELECT * FROM dns_node_history WHERE node_ip = ?'
                ).bind(cleanIp).first();

                if (existing) {
                    const newTotal = (existing.total_count || 0) + 1;
                    const newSuccess = (existing.success_count || 0) + (node.success ? 1 : 0);
                    const newAvg = node.success
                        ? ((existing.avg_latency || 0) * (existing.total_count || 0) + node.latency) / newTotal
                        : existing.avg_latency || 0;

                    await env.DB.prepare(
                        'UPDATE dns_node_history SET total_count = ?, success_count = ?, avg_latency = ?, last_seen = ? WHERE node_ip = ?'
                    ).bind(newTotal, newSuccess, Math.round(newAvg), nowBeijing, cleanIp).run();
                } else {
                    await env.DB.prepare(
                        'INSERT INTO dns_node_history (node_ip, total_count, success_count, avg_latency, last_seen) VALUES (?, ?, ?, ?, ?)'
                    ).bind(cleanIp, 1, node.success ? 1 : 0, node.success ? node.latency : 0, nowBeijing).run();
                }
            } catch(e) {}
        }

        return {
            success: true,
            message: `自动更新成功：【${config.isp_type}】测试${testIPs.length}个节点，${successNodes.length}个可用，已推送TOP${topNodes.length}到DNS`,
            topNodes: topNodes.map(n => ({ ip: n.ip, latency: n.latency, score: n.score })),
            stats: { tested: testIPs.length, available: successNodes.length },
            config: config
        };
    } catch(e) {
        // 记录失败历史
        try {
            const nowBeijing = new Date(Date.now() + 8 * 3600000).toISOString().replace('T', ' ').split('.')[0];
            await env.DB.prepare(
                `INSERT INTO dns_update_history (nodes_json, trigger_type, total_tested, success_count, error_msg, created_at) VALUES (?, ?, ?, ?, ?, ?)`
            ).bind('[]', 'auto', 0, 0, e.message, nowBeijing).run();
        } catch(e2) {}

        return { success: false, error: e.message };
    }
}

export default {
    // ==========================================
    // 🔧 通用数据库初始化函数（用于 scheduled 任务）
    // ==========================================
    async initDatabaseForScheduled(env) {
        if (!env.DB) return false;
        try {
            // 智能DNS表初始化
            await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_update_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nodes_json TEXT DEFAULT '[]',
                trigger_type TEXT DEFAULT 'auto',
                total_tested INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                error_msg TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);
            await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_node_history (
                node_ip TEXT PRIMARY KEY,
                total_count INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                avg_latency INTEGER DEFAULT 0,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);
            return true;
        } catch(e) {
            console.error("DB init for scheduled error:", e.message);
            return false;
        }
    },
    
    // 每天6小时自动运行发送 TG 统计 + 智能DNS更新
    async scheduled(event, env, ctx) {
        // 先初始化数据库
        if (env.DB) {
            await this.initDatabaseForScheduled(env);
        }
        
        // 原有TG播报
        if (env.TG_BOT_TOKEN && env.TG_CHAT_ID && env.DB) {
            ctx.waitUntil(sendTgStats(env, env.TG_CHAT_ID));
        }

        // 新增：智能DNS自动更新（每6小时触发）
        if (env.DB && env.CF_API_TOKEN && env.CF_ZONE_ID && env.CF_DOMAIN) {
            ctx.waitUntil((async () => {
                const result = await autoUpdateDNS(env);
                console.log('Auto DNS Update Result:', JSON.stringify(result));

                // 如果有TG Bot，发送更新通知（检查Bot开关）
                if (env.TG_BOT_TOKEN && env.TG_CHAT_ID && result.success) {
                    let shouldNotify = true;
                    try {
                        const botCfg = await env.DB.prepare('SELECT bot_enabled FROM bot_config WHERE id = 1').first();
                        if (botCfg && !botCfg.bot_enabled) shouldNotify = false;
                    } catch(e) {}
                    
                    if (shouldNotify) {
                        const msg = `\u{1F916} *智能DNS自动更新*\n\n${result.message}\n\n\u{1F3C6} *TOP节点:*\n${result.topNodes.map((n, i) => `#${i+1} ${n.ip} (${n.latency}ms, \u8BC4\u5206${n.score})`).join('\n')}`;
                        await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ chat_id: env.TG_CHAT_ID, text: msg, parse_mode: 'Markdown' })
                        });
                    }
                }
            })());
        }

        // 新增：多线子域名自动调度（每6小时触发，yd/lt/dx 按各自运营商推送）
        if (env.DB && env.CF_API_TOKEN && env.CF_ZONE_ID && env.CF_DOMAIN) {
            ctx.waitUntil((async () => {
                const subResult = await autoUpdateAllSubdomains(env);
                console.log('Auto Subdomain DNS Update Result:', JSON.stringify(subResult));
                if (env.TG_BOT_TOKEN && env.TG_CHAT_ID && subResult.success) {
                    let shouldNotify = true;
                    try {
                        const botCfg = await env.DB.prepare('SELECT bot_enabled FROM bot_config WHERE id = 1').first();
                        if (botCfg && !botCfg.bot_enabled) shouldNotify = false;
                    } catch(e) {}
                    if (shouldNotify) {
                        const lines = (subResult.results || []).map(r => {
                            if (r.skipped) return `⏸️ ${r.sub}. 已停用`;
                            if (r.success) return `✅ ${r.sub} (${r.ispType}) → ${r.topNodes.map(n => n.ip).join(', ')}`;
                            return `❌ ${r.sub} (${r.ispType}): ${r.error}`;
                        });
                        const msg = `\u{1F916} *多线子域名自动调度*\n\n${lines.join('\n')}`;
                        await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ chat_id: env.TG_CHAT_ID, text: msg, parse_mode: 'Markdown' })
                        });
                    }
                }
            })());
        }
    },

    async fetch(request, env, ctx) {
        try {
        const url = new URL(request.url);
        if (env.DB) globalThis.__fdDB = env.DB; // 供模块级故障转移缓存写回 D1

        // 新增表幂等确保（每 isolate 首次请求执行一次，避免各新接口反复 DDL）
        if (env.DB && !globalThis.__fdTables) {
            globalThis.__fdTables = true;
            try {
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS node_health (target TEXT PRIMARY KEY, status TEXT DEFAULT 'up', ts INTEGER DEFAULT 0)`);
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS failover_log (id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT, target TEXT, ts INTEGER, reason TEXT)`);
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS system_config (key TEXT PRIMARY KEY, value TEXT)`);
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS node_ping_history (id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT, target TEXT, ts INTEGER, ms INTEGER)`);
                try { await env.DB.exec(`ALTER TABLE visitor_logs ADD COLUMN lat REAL DEFAULT 0`); } catch(e) {}
                try { await env.DB.exec(`ALTER TABLE visitor_logs ADD COLUMN lon REAL DEFAULT 0`); } catch(e) {}
                try { await env.DB.exec(`ALTER TABLE visitor_logs ADD COLUMN city TEXT DEFAULT ''`); } catch(e) {}
                // 治愈历史遗留异结构 system_config：探测失败则 DROP 重建（新表，仅存 failover 计数/开关）
                try {
                    await env.DB.prepare('SELECT key, value FROM system_config LIMIT 1').first();
                } catch (e) {
                    try {
                        await env.DB.exec('DROP TABLE IF EXISTS system_config');
                        await env.DB.exec('CREATE TABLE system_config (key TEXT PRIMARY KEY, value TEXT)');
                    } catch (e2) {}
                }
            } catch(e) { globalThis.__fdTables = false; }
        }
        
        // ==========================================
        // 🔧 通用数据库初始化函数：确保所有表都存在
        // ==========================================
        async function initDatabase(env) {
            if (!env.DB) return false;
            try {
                // 基础表
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS routes (prefix TEXT PRIMARY KEY, target TEXT NOT NULL)`);
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS request_stats (prefix TEXT, date TEXT, count INTEGER DEFAULT 0, PRIMARY KEY(prefix, date))`);
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS visitor_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, ip TEXT, country TEXT, ua TEXT)`);
                
                // 智能DNS表
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_update_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nodes_json TEXT DEFAULT '[]',
                    trigger_type TEXT DEFAULT 'auto',
                    total_tested INTEGER DEFAULT 0,
                    success_count INTEGER DEFAULT 0,
                    error_msg TEXT DEFAULT '',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`);
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_node_history (
                    node_ip TEXT PRIMARY KEY,
                    total_count INTEGER DEFAULT 0,
                    success_count INTEGER DEFAULT 0,
                    avg_latency INTEGER DEFAULT 0,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )`);
                
                // 尝试添加列（已经存在的会跳过）
                try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN mode TEXT DEFAULT 'off'`); } catch(e) {}
                try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN remark TEXT DEFAULT ''`); } catch(e) {}
                try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN last_play TEXT DEFAULT ''`); } catch(e) {}
                try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN icon TEXT DEFAULT ''`); } catch(e) {}
                try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN cache_img TEXT DEFAULT 'on'`); } catch(e) {} 
                try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN sort_order INTEGER DEFAULT 0`); } catch(e) {}
                
                // 多线子域名调度表
                await ensureDnsTables(env);
                
                // 优选域名测速缓存（按客户端网段）
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS domain_speed_cache (cache_key TEXT PRIMARY KEY, results_json TEXT, ts INTEGER DEFAULT 0)`);

                // 运行时故障转移 / 测速历史 / 系统配置
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS node_health (target TEXT PRIMARY KEY, status TEXT DEFAULT 'up', ts INTEGER DEFAULT 0)`);
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS failover_log (id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT, target TEXT, ts INTEGER, reason TEXT)`);
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS system_config (key TEXT PRIMARY KEY, value TEXT)`);
                await env.DB.exec(`CREATE TABLE IF NOT EXISTS node_ping_history (id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT, target TEXT, ts INTEGER, ms INTEGER)`);
                try { await env.DB.exec(`ALTER TABLE visitor_logs ADD COLUMN lat REAL DEFAULT 0`); } catch(e) {}
                try { await env.DB.exec(`ALTER TABLE visitor_logs ADD COLUMN lon REAL DEFAULT 0`); } catch(e) {}
                try { await env.DB.exec(`ALTER TABLE visitor_logs ADD COLUMN city TEXT DEFAULT ''`); } catch(e) {}
                // 治愈历史遗留异结构 system_config：探测失败则 DROP 重建
                try {
                    await env.DB.prepare('SELECT key, value FROM system_config LIMIT 1').first();
                } catch (e) {
                    try {
                        await env.DB.exec('DROP TABLE IF EXISTS system_config');
                        await env.DB.exec('CREATE TABLE system_config (key TEXT PRIMARY KEY, value TEXT)');
                    } catch (e2) {}
                }

                return true;
            } catch(e) {
                console.error("Database init error:", e.message);
                return false;
            }
        }

        // ==========================================
        // 🚀 新增：全云厂商 Worker 放置区域接口
        // ==========================================
        if (url.pathname === '/api/placement' && request.method === 'POST') {
            try {
                const body = await request.json();
                const placementData = body.placement; 
                
                if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID || !env.CF_WORKER_NAME) {
                    return new Response(JSON.stringify({ success: false, msg: '后台变量未配置全！请检查 CF_API_TOKEN, CF_ACCOUNT_ID, CF_WORKER_NAME' }), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }});
                }
                
                const formData = new FormData();
                formData.append('settings', new Blob([JSON.stringify({ placement: placementData })], { type: 'application/json' }));

                const cfUrl = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/workers/scripts/${env.CF_WORKER_NAME}/settings`;
                const cfRes = await fetch(cfUrl, {
                    method: 'PATCH',
                    headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` },
                    body: formData 
                });
                
                const cfData = await cfRes.json();
                if (cfData.success) {
                    return new Response(JSON.stringify({ success: true, msg: '部署区域修改成功！' }), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }});
                } else {
                    return new Response(JSON.stringify({ success: false, msg: 'CF报错: ' + (cfData.errors[0]?.message || '未知错误') }), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }});
                }
            } catch(e) {
                return new Response(JSON.stringify({ success: false, msg: e.message }), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }});
            }
        }

        // ==========================================
        // 🚀 新增：CF 节点与落地机房探针接口
        // ==========================================
        if (url.pathname === '/api/trace') {
            const cf = request.cf || {};
            let egressColo = '探测中...';
            try {
                // 请求 CF 官方 trace 接口获取落地机房
                const traceRes = await fetch('https://1.1.1.1/cdn-cgi/trace', {
                    headers: { 'User-Agent': 'Mozilla/5.0 (CF-Worker-Trace)' }
                });
                const traceText = await traceRes.text();
                const match = traceText.match(/colo=([A-Z]+)/);
                if (match) egressColo = match[1];
            } catch(e) {
                egressColo = '获取失败';
            }

            return new Response(JSON.stringify({
                success: true,
                entryCountry: cf.country || '未知',
                entryCity: cf.city || '',
                entryColo: cf.colo || '未知',
                egressColo: egressColo
            }), {
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }

        // ==========================================
        // 🌟 新增：客户端 RTT 实时极速探针接口
        // 直接返回 204 无内容，且强制不缓存，确保每次都是真实的物理延迟
        // ==========================================
        if (url.pathname === '/__client_rtt__') {
            return new Response(null, {
                status: 204,
                headers: {
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                    "Access-Control-Allow-Origin": "*"
                }
            });
        }

        // Telegram Webhook 拦截
        if (url.pathname === '/api/tg-webhook' && request.method === 'POST') {
            try {
                const body = await request.json();
                if (body.message && body.message.text === '/stats') {
                    if (env.DB && env.TG_BOT_TOKEN) {
                        ctx.waitUntil(sendTgStats(env, body.message.chat.id));
                    }
                }
                return new Response("OK");
            } catch(e) { return new Response("OK"); }
        }

        // Telegram 机器人控制台 - 发送消息接口
        if (url.pathname === '/api/send-tg-message' && request.method === 'POST') {
            try {
                if (!env.TG_BOT_TOKEN || !env.TG_CHAT_ID) {
                    return Response.json({ success: false, error: '未配置 TG_BOT_TOKEN 或 TG_CHAT_ID' });
                }
                
                // 检查Bot推送开关
                try {
                    const botCfg = await env.DB.prepare('SELECT bot_enabled FROM bot_config WHERE id = 1').first();
                    if (botCfg && !botCfg.bot_enabled) {
                        return Response.json({ success: false, error: 'Bot推送已关闭，请在面板中开启' });
                    }
                } catch(e) {}
                const body = await request.json();
                const type = body.type || 'stats';
                let message = '';

                if (type === 'stats') {
                    // 发送完整统计
                    ctx.waitUntil(sendTgStats(env, env.TG_CHAT_ID));
                    return Response.json({ success: true, message: '完整播报已发送' });
                } else if (type === 'today') {
                    // 今日简报
                    const totalQuery = await env.DB.prepare(`SELECT COUNT(*) as count FROM visitor_logs WHERE date(timestamp, '+8 hours') = date('now', '+8 hours')`).first();
                    const totalToday = totalQuery ? totalQuery.count : 0;
                    message = '📋 *今日访问简报*\n\n▶️ 今日总播放: ' + totalToday + ' 次\n📅 日期: ' + new Date().toLocaleDateString('zh-CN') + '\n\n_来自 智能反代系统面板_';
                } else if (type === 'top') {
                    // 节点热度
                    const topQuery = await env.DB.prepare(`SELECT prefix, COUNT(*) as count FROM visitor_logs GROUP BY prefix ORDER BY count DESC LIMIT 5`).all();
                    let topText = '';
                    if (topQuery && topQuery.results) {
                        topQuery.results.forEach((r, i) => {
                            topText += (i + 1) + '. /' + r.prefix + ' — ' + r.count + ' 次\n';
                        });
                    }
                    message = '🏆 *节点热度 TOP5*\n\n' + (topText || '暂无数据') + '\n_来自 智能反代系统面板_';
                } else if (type === 'clients') {
                    // 客户端分布
                    const uaQuery = await env.DB.prepare(`SELECT ua, COUNT(*) as count FROM visitor_logs GROUP BY ua ORDER BY count DESC LIMIT 5`).all();
                    let uaText = '';
                    if (uaQuery && uaQuery.results) {
                        uaQuery.results.forEach((r, i) => {
                            const uaShort = r.ua ? r.ua.substring(0, 30) + (r.ua.length > 30 ? '...' : '') : 'Unknown';
                            uaText += (i + 1) + '. ' + uaShort + ' — ' + r.count + ' 次\n';
                        });
                    }
                    message = '👥 *客户端分布 TOP5*\n\n' + (uaText || '暂无数据') + '\n_来自 智能反代系统面板_';
                }

                if (message) {
                    await fetch('https://api.telegram.org/bot' + env.TG_BOT_TOKEN + '/sendMessage', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ chat_id: env.TG_CHAT_ID, text: message, parse_mode: 'Markdown' })
                    });
                }

                return Response.json({ success: true, message: type + ' 消息已发送' });
            } catch(e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // Bot推送配置API
        if (url.pathname === '/api/bot-config') {
            try {
                if (!env.DB) {
                    return Response.json({ success: false, error: '未绑定数据库' });
                }
                
                // 初始化表
                try { await env.DB.exec(`CREATE TABLE IF NOT EXISTS bot_config (id INTEGER PRIMARY KEY DEFAULT 1, bot_enabled INTEGER DEFAULT 1, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); } catch(e) {}
                try { await env.DB.prepare(`INSERT OR IGNORE INTO bot_config (id, bot_enabled) VALUES (1, 1)`).run(); } catch(e) {}
                
                if (request.method === 'GET') {
                    const cfg = await env.DB.prepare('SELECT bot_enabled FROM bot_config WHERE id = 1').first();
                    return Response.json({
                        success: true,
                        enabled: cfg ? !!cfg.bot_enabled : true
                    });
                }
                
                if (request.method === 'POST') {
                    const body = await request.json();
                    const enabled = body.enabled ? 1 : 0;
                    await env.DB.prepare(`INSERT OR REPLACE INTO bot_config (id, bot_enabled, updated_at) VALUES (1, ?, datetime('now', '+8 hours'))`).bind(enabled).run();
                    return Response.json({ 
                        success: true, 
                        enabled: !!enabled,
                        message: enabled ? 'Bot推送已开启' : 'Bot推送已关闭'
                    });
                }
            } catch(e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        if (request.method === "OPTIONS") {
            return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS", "Access-Control-Allow-Headers": "*", "Access-Control-Max-Age": "86400" } });
        }

        const EXPECTED_TOKEN = env.ADMIN_TOKEN;
        if (!EXPECTED_TOKEN) return new Response("请在 Worker 变量中配置 ADMIN_TOKEN", { status: 500 });

        function getCookie(req, name) {
            const cookieString = req.headers.get("Cookie");
            if (!cookieString) return null;
            const match = cookieString.match(new RegExp('(^| )' + name + '=([^;]+)'));
            if (match) return decodeURIComponent(match[2]);
            return null;
        }

        const isPanelOrApi = url.pathname === '/admin' || url.pathname.startsWith('/api/');
        const publicApi = url.pathname === '/api/tg-webhook' || url.pathname === '/api/health' || url.pathname === '/api/domains/speed';
        if (isPanelOrApi && !publicApi) {
            const providedToken = getCookie(request, 'admin_token');
            if (providedToken !== EXPECTED_TOKEN) {
                if (url.pathname === '/admin') return new Response(LOGIN_UI, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
                else return new Response('Unauthorized', { status: 401 });
            }
        }

        // 📱 PWA manifest（公开）
        if (url.pathname === '/manifest.webmanifest') {
            const iconSvg = encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" rx="22" fill="#10b981"/><text x="50" y="64" font-size="46" text-anchor="middle">🚀</text></svg>`);
            const manifest = {
                name: '智能反代系统',
                short_name: '智能反代',
                description: '智能反代系统 · 访问地址导航',
                start_url: '/',
                scope: '/',
                display: 'standalone',
                background_color: '#0f1115',
                theme_color: '#10b981',
                icons: [{ src: 'data:image/svg+xml,' + iconSvg, sizes: 'any', type: 'image/svg+xml', purpose: 'any' }]
            };
            return new Response(JSON.stringify(manifest), { headers: { 'Content-Type': 'application/manifest+json', 'Cache-Control': 'public, max-age=3600' } });
        }

        // 📱 PWA Service Worker（公开）：缓存导航页实现离线查看地址
        if (url.pathname === '/sw.js') {
            const swCode = `const CACHE='fandai-landing-v1';
self.addEventListener('install',e=>{self.skipWaiting();});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET') return;
  const u=new URL(e.request.url);
  if(u.pathname==='/sw.js'||u.pathname==='/manifest.webmanifest') return;
  e.respondWith(
    fetch(e.request).then(res=>{
      if(res.ok && u.origin===location.origin){ const c=res.clone(); caches.open(CACHE).then(ca=>ca.put(e.request,c)); }
      return res;
    }).catch(()=>caches.match(e.request).then(m=>m||caches.match('/')))
  );
});`;
            return new Response(swCode, { headers: { 'Content-Type': 'application/javascript', 'Cache-Control': 'public, max-age=3600' } });
        }

        // 地址导航页（公开）：主域 + 三子域的 `/` 均打开此页
        if (url.pathname === '/') {
            let landingHtml = LANDING_UI;
            if (env.DB) {
                try {
                    const { results } = await env.DB.prepare("SELECT prefix, remark, icon FROM routes ORDER BY sort_order").all();
                    if (results && results.length) {
                        const list = results.map(r => {
                            const name = escapeHtml(r.remark || r.prefix);
                            const prefix = escapeHtml(r.prefix);
                            const icon = String(r.icon || '').trim();
                            const iconHtml = icon
                                ? `<img src="${escapeHtml(icon)}" alt="" onerror="this.style.display='none';this.parentElement.textContent='🎬'">`
                                : '🎬';
                            return `<div class="svc"><div class="svc-icon">${iconHtml}</div><div class="svc-info"><div class="svc-name">${name}</div><div class="svc-prefix">/${prefix}</div></div><div class="svc-status loading" data-prefix="/${prefix}" title="检测中..."></div></div>`;
                        }).join('');
                        landingHtml = landingHtml.replace('<!-- SERVICES -->', `<details class="services"><summary>支持的服务</summary><div class="svc-list">${list}</div></details>`);
                    }
                } catch (e) { console.error('Landing routes error:', e); }
            }
            return new Response(landingHtml, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
        }

        // 后台管理面板：https://fandai.erebus.de5.net/admin
        if (url.pathname === '/admin') {
            return new Response(HTML_UI, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
        }

        // ==========================================
        // 2.3 数据大屏统计接口 (Analytics)
        // ==========================================
        if (url.pathname === '/api/analytics' && request.method === 'GET') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定 D1 数据库' });
            try {
                // 并发获取 24小时、7天、30天流量 (通过全新 GraphQL API 规避限制)
                const [trafficToday, traffic7d, traffic30d] = await Promise.all([
                    getCFTraffic(env, 'today'),
                    getCFTraffic(env, 7),
                    getCFTraffic(env, 30)
                ]);

                const trend = await env.DB.prepare(`SELECT date(timestamp, '+8 hours') as date, COUNT(*) as count FROM visitor_logs WHERE timestamp >= datetime('now', '-7 days') GROUP BY date(timestamp, '+8 hours') ORDER BY date ASC`).all();
                const locations = await env.DB.prepare(`SELECT country, COUNT(*) as count FROM visitor_logs WHERE timestamp >= datetime('now', '-7 days') GROUP BY country ORDER BY count DESC`).all();
                const recents = await env.DB.prepare(`SELECT prefix, datetime(timestamp, '+8 hours') as timestamp, ip, country, ua FROM visitor_logs ORDER BY timestamp DESC LIMIT 20`).all();
                const todayStr = new Date(Date.now() + 8 * 3600000).toISOString().split('T')[0];
                const foRow = await env.DB.prepare('SELECT value FROM system_config WHERE key = ?').bind('failover_' + todayStr).first();
                const failoverToday = foRow && foRow.value ? (parseInt(foRow.value, 10) || 0) : 0;
                const foEnabledRow = await env.DB.prepare('SELECT value FROM system_config WHERE key = ?').bind('failover_enabled').first();
                const failoverEnabled = foEnabledRow ? foEnabledRow.value !== 'off' : true;

                return Response.json({
                    success: true,
                    trend: trend.results,
                    locations: locations.results,
                    recents: recents.results,
                    trafficToday, traffic7d, traffic30d,
                    failoverToday, failoverEnabled
                });
            } catch(e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // 系统配置读写（故障转移开关等）
        if (url.pathname === '/api/get-cfg') {
            if (!env.DB) return Response.json({ success: false, value: null });
            try {
                const key = url.searchParams.get('key');
                if (!key) return Response.json({ success: false, value: null });
                const val = await getCfg(env, key, null);
                return Response.json({ success: true, value: val });
            } catch (e) { return Response.json({ success: false, value: null }); }
        }

        if (url.pathname === '/api/set-cfg' && request.method === 'POST') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定 D1' });
            try {
                const body = await request.json();
                if (!body.key) return Response.json({ success: false, error: '缺少 key' });
                await setCfg(env, body.key, body.value);
                return Response.json({ success: true });
            } catch (e) { return Response.json({ success: false, error: e.message }); }
        }

        // ==========================================
        // 🟢 后端接口：执行代码覆盖更新 (纯JSON接口无损继承：变量、数据库、兼容性、放置地区)
        // ==========================================
        if (url.pathname === '/api/deploy' && request.method === 'POST') {
            const cfToken = env.CF_API_TOKEN;
            const accountId = env.CF_ACCOUNT_ID;
            const workerName = env.CF_WORKER_NAME;
            if (!cfToken || !accountId || !workerName) {
                return Response.json({ success: false, error: '缺少 CF_API_TOKEN, CF_ACCOUNT_ID 或 CF_WORKER_NAME 环境变量' });
            }
            try {
                const body = await request.json();
                if (!body.newCode) return Response.json({ success: false, error: '代码内容为空。' });

                // 1. 🚀 终极修复：调用纯 JSON 的 services 接口获取真实配置，绝对不再崩溃！
                const serviceRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/services/${workerName}`, {
                    headers: { 'Authorization': `Bearer ${cfToken}` }
                });
                const serviceData = await serviceRes.json();
                
                let compDate = "2024-01-01"; // 依然保留兜底，但这次绝不会用到
                let compFlags = undefined;
                let placement = undefined;

                if (serviceData.success && serviceData.result) {
                    // 精准从 JSON 中提取你原本的配置
                    let scriptInfo = null;
                    if (serviceData.result.default_environment && serviceData.result.default_environment.script) {
                        scriptInfo = serviceData.result.default_environment.script;
                    } else if (serviceData.result.script) {
                        scriptInfo = serviceData.result.script;
                    }
                    
                    if (scriptInfo) {
                        if (scriptInfo.compatibility_date) compDate = scriptInfo.compatibility_date;
                        if (scriptInfo.compatibility_flags) compFlags = scriptInfo.compatibility_flags;
                        if (scriptInfo.placement) placement = scriptInfo.placement;
                    }
                }

                const preservedBindings = [];
                // 2. 备份普通的字符串变量
                for (const key in env) {
                    if (typeof env[key] === 'string') {
                        preservedBindings.push({ name: key, type: 'plain_text', text: env[key] });
                    }
                }

                // 3. 拉取 D1、KV 等高级绑定并无损合并
                const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}/bindings`, {
                    headers: { 'Authorization': `Bearer ${cfToken}` }
                });
                const bindingsData = await bindingsRes.json();
                if (bindingsData.success && Array.isArray(bindingsData.result)) {
                    for (const b of bindingsData.result) {
                        if (b.type !== 'plain_text' && b.type !== 'secret_text' && b.type !== 'inherited') {
                            preservedBindings.push(b);
                        }
                    }
                }

                // 4. 组装最终的部署请求
                const formData = new FormData();
                const metadata = { 
                    main_module: 'worker.js',
                    bindings: preservedBindings,
                    compatibility_date: compDate 
                };
                if (compFlags) metadata.compatibility_flags = compFlags;
                if (placement) metadata.placement = placement; // 🎯 完美带上你原始的放置地区！

                formData.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }), 'metadata.json');
                formData.append('worker.js', new Blob([body.newCode], { type: 'application/javascript+module' }), 'worker.js');

                const cfUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`;
                const res = await fetch(cfUrl, {
                    method: 'PUT',
                    headers: { 'Authorization': `Bearer ${cfToken}` },
                    body: formData
                });
                const data = await res.json();
                if (data.success) {
                    return Response.json({ success: true, msg: '代码更新成功，并已完美保留原有放置地区和兼容配置！' });
                } else {
                    throw new Error(JSON.stringify(data.errors));
                }
            } catch (e) {
                return Response.json({ success: false, error: e.message });
            }
        }
        // ==========================================
        // 2.4 系统级与提取工具 API 
        // ==========================================
        if (url.pathname === '/api/purge-cache' && request.method === 'POST') {
            const cfToken = env.CF_API_TOKEN; const zoneId = env.CF_ZONE_ID;
            if (!cfToken || !zoneId) return Response.json({ success: false, error: '缺少 CF_API_TOKEN 或 CF_ZONE_ID 变量' });
            try {
                const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/purge_cache`, { method: 'POST', headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ purge_everything: true }) });
                const data = await res.json();
                if (!data.success) throw new Error(JSON.stringify(data.errors));
                return Response.json({ success: true });
            } catch (e) { return Response.json({ success: false, error: e.message }); }
        }

        if (url.pathname === '/api/ping-node') {
            const target = url.searchParams.get('url');
            const prefix = url.searchParams.get('prefix') || '';
            if (!target) return Response.json({ ms: -1 });
            const start = Date.now();
            let ms = -1;
            try {
                const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), 2000); 
                await fetch(target + '/', { method: 'HEAD', signal: controller.signal });
                clearTimeout(timeoutId); ms = Date.now() - start;
            } catch (e) { ms = -1; }
            // 📉 测速历史：写入 node_ping_history 供 7 天延迟趋势图使用
            if (env.DB && ms >= 0) {
                try {
                    await env.DB.prepare('INSERT INTO node_ping_history (prefix, target, ts, ms) VALUES (?, ?, ?, ?)')
                        .bind(prefix || 'direct', target, Date.now(), ms).run();
                } catch (e) {}
            }
            return Response.json({ ms });
        }

        if (url.pathname === '/api/ping-history') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定 D1' });
            try {
                const days = 7;
                const since = Date.now() - days * 86400000;
                const { results } = await env.DB.prepare(
                    'SELECT prefix, date(ts/1000, "unixepoch", "+8 hours") as day, CAST(AVG(ms) AS INTEGER) as avg_ms, MIN(ms) as min_ms, MAX(ms) as max_ms, COUNT(*) as n FROM node_ping_history WHERE ts >= ? GROUP BY prefix, date(ts/1000, "unixepoch", "+8 hours") ORDER BY day ASC'
                ).bind(since).all();
                return Response.json({ success: true, days, points: results });
            } catch (e) { return Response.json({ success: false, error: e.message }); }
        }

        if (url.pathname === '/api/get-dns') {
            const cfToken = env.CF_API_TOKEN; const zoneId = env.CF_ZONE_ID; const domain = env.CF_DOMAIN;
            if (!cfToken || !zoneId || !domain) return Response.json({ success: false, error: '缺少 DNS 环境变量' });
            try {
                const getRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?name=${domain}`, { headers: { 'Authorization': `Bearer ${cfToken}` } });
                const getData = await getRes.json();
                return Response.json({ success: true, result: getData.result });
            } catch (error) { return Response.json({ success: false, error: error.message }); }
        }

        if (url.pathname === '/api/update-dns' && request.method === 'POST') {
            const body = await request.json(); const ips = body.ips;
            const cfToken = env.CF_API_TOKEN; const zoneId = env.CF_ZONE_ID; const domain = env.CF_DOMAIN;

            if (!cfToken || !zoneId || !domain) return Response.json({ success: false, error: '缺少 DNS 环境变量' });
            try {
                const getRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?name=${domain}`, { headers: { 'Authorization': `Bearer ${cfToken}` } });
                const getData = await getRes.json();
                if (!getData.success) throw new Error('获取现有 DNS 记录失败');

                const oldRecords = getData.result.filter(r => r.type === 'A' || r.type === 'AAAA' || r.type === 'CNAME');
                for (const record of oldRecords) {
                    await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${record.id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${cfToken}` } });
                }

                for (const ip of ips) {
                    const cleanItem = ip.replace(/[\[\]]/g, ''); let recordType = 'A';
                    if (cleanItem.includes(':')) recordType = 'AAAA'; else if (/[a-zA-Z]/.test(cleanItem)) recordType = 'CNAME';

                    const postRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, { method: 'POST', headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ type: recordType, name: domain, content: cleanItem, ttl: 60, proxied: false }) });
                    const postData = await postRes.json();
                    if(!postData.success) throw new Error(`记录提交失败: ` + JSON.stringify(postData.errors));
                }
                return Response.json({ success: true, message: `✅ 成功！` });
            } catch (error) { return Response.json({ success: false, error: error.message }); }
        }

        if (url.pathname === '/api/get-custom-api-ips') {
            try {
                const apiUrl = url.searchParams.get('url');
                if (!apiUrl) throw new Error("缺少 URL");
                const response = await fetch(apiUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } });
                const text = await response.text(); let validIPs = new Set();
                try {
                    const jsonObj = JSON.parse(text);
                    if (jsonObj && jsonObj.data && Array.isArray(jsonObj.data)) {
                        jsonObj.data.forEach(item => { if (item.ip) { let ip = item.ip; if (ip.includes(':') && !ip.startsWith('[')) ip = `[${ip}]`; validIPs.add(ip); } });
                    }
                } catch (e) {}

                if (validIPs.size === 0) {
                    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
                    const matchedIPv4 = text.match(ipv4Regex) || [];
                    matchedIPv4.forEach(ip => { if (!ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.')) validIPs.add(ip); });

                    const ipv6Regex = /(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?:[A-F0-9]{1,4}:)*:[A-F0-9]{1,4}(?::[A-F0-9]{1,4})*/gi;
                    const matchedIPv6 = text.match(ipv6Regex) || [];
                    matchedIPv6.forEach(ip => { if (ip.length > 7 && ip.includes(':') && !ip.startsWith('::1')) validIPs.add(ip.startsWith('[') ? ip : `[${ip}]`); });
                }
                const uniqueIPArray = Array.from(validIPs);
                for (let i = uniqueIPArray.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [uniqueIPArray[i], uniqueIPArray[j]] = [uniqueIPArray[j], uniqueIPArray[i]]; }
                return Response.json({ success: true, ips: uniqueIPArray.slice(0, 15), totalCount: uniqueIPArray.length });
            } catch (error) { return Response.json({ success: false, error: error.message }, { status: 500 }); }
        }

        if (url.pathname === '/api/get-remote-ips') {
            try {
                const reqType = (url.searchParams.get('type') || 'all').toLowerCase();
                const validIPs = new Set();

                if (['all', '电信', '联通', '移动', '多线', 'ipv6'].includes(reqType)) {
                    try {
                        const res1 = await fetch('https://api.uouin.com/cloudflare.html', { headers: { 'User-Agent': 'Mozilla/5.0' } });
                        if(res1.ok) {
                            const text1 = await res1.text(); const cleanText = text1.replace(/<[^>]+>/g, ' ');
                            const regex = /(电信|联通|移动|多线|ipv6)\s+((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)|(?:[a-fA-F0-9]{1,4}:)+[a-fA-F0-9]{1,4})/gi;
                            let match; while ((match = regex.exec(cleanText)) !== null) {
                                const lineType = match[1].toLowerCase(); let ip = match[2];
                                if (ip.includes(':') && !ip.startsWith('[')) ip = `[${ip}]`;
                                if (reqType === 'all' || reqType === lineType) validIPs.add(ip);
                            }
                        }
                    } catch(e) {}
                }

                if (['all', '优选'].includes(reqType)) {
                    try {
                        const res2 = await fetch('https://raw.githubusercontent.com/ZhiXuanWang/cf-speed-dns/refs/heads/main/ipTop10.html', { headers: { 'User-Agent': 'Mozilla/5.0' } });
                        if(res2.ok) {
                            const text2 = await res2.text(); const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
                            const matched = text2.match(ipv4Regex) || []; matched.forEach(ip => { if (!ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.')) validIPs.add(ip); });
                        }
                    } catch(e) {}
                }
                const uniqueIPArray = Array.from(validIPs);
                for (let i = uniqueIPArray.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [uniqueIPArray[i], uniqueIPArray[j]] = [uniqueIPArray[j], uniqueIPArray[i]]; }
                return Response.json({ success: true, ips: uniqueIPArray.slice(0, 10), totalCount: uniqueIPArray.length });
            } catch (error) { return Response.json({ success: false, error: error.message }, { status: 500 }); }
        }


        // 手动触发智能DNS更新
        if (url.pathname === '/api/auto-dns-update' && request.method === 'POST') {
            if (env.DB) {
                await initDatabase(env);
            }
            const result = await autoUpdateDNS(env);
            return Response.json(result);
        }

        // 获取自动更新历史记录
        if (url.pathname === '/api/dns-history' && request.method === 'GET') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定数据库' });
            try {
                // 先确保数据库表初始化
                await initDatabase(env);
                
                const { results } = await env.DB.prepare(
                    'SELECT * FROM dns_update_history ORDER BY created_at DESC LIMIT 30'
                ).all();
                return Response.json({ success: true, history: results });
            } catch(e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // 获取自动更新配置
        if (url.pathname === '/api/auto-dns-config' && request.method === 'GET') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定数据库' });
            try {
                await initDatabase(env);
                let cfg = await env.DB.prepare('SELECT isp_type, top_n, updated_at FROM dns_auto_config WHERE id = 1').first();
                if (!cfg) {
                    await env.DB.prepare(`INSERT INTO dns_auto_config (id, isp_type, top_n) VALUES (1, '移动', 3)`).run();
                    cfg = { isp_type: '移动', top_n: 3 };
                }
                return Response.json({
                    success: true,
                    config: {
                        enabled: true,
                        interval: '6h',
                        isp: cfg.isp_type || '移动',
                        topN: cfg.top_n || 3,
                        defaultType: cfg.isp_type || '移动'
                    }
                });
            } catch(e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // 更新自动更新配置
        if (url.pathname === '/api/auto-dns-config' && request.method === 'POST') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定数据库' });
            try {
                await initDatabase(env);
                const body = await request.json();
                const ispType = body.isp_type || body.isp || '移动';
                const topN = parseInt(body.top_n || body.topN || 3);
                await env.DB.prepare(
                    `INSERT OR REPLACE INTO dns_auto_config (id, isp_type, top_n, updated_at) VALUES (1, ?, ?, datetime('now', '+8 hours'))`
                ).bind(ispType, topN).run();
                return Response.json({ success: true, message: '配置已保存', config: { isp_type: ispType, top_n: topN } });
            } catch(e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // ==========================================
        // 🌐 多线子域名调度 API（yd=移动 / lt=联通 / dx=电信）
        // ==========================================
        // 获取子域名调度配置
        if (url.pathname === '/api/subdomain-config' && request.method === 'GET') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定数据库' });
            try {
                await initDatabase(env);
                const subBase = (env.CF_DOMAIN || '').split('.').slice(1).join('.') || env.CF_DOMAIN;
                const rows = (await env.DB.prepare('SELECT sub, isp_type, top_n, enabled FROM dns_subdomain_config ORDER BY sub').all()).results || [];
                const ispMap = { '移动': '🟢 移动', '电信': '🔵 电信', '联通': '🟠 联通', '多线': '🟣 多线', 'ipv6': '🚀 IPv6', '优选': '🌟 优选', 'all': '🌐 混合' };
                const data = rows.map(r => ({
                    sub: r.sub,
                    domain: r.sub + '.' + subBase,
                    ispType: r.isp_type,
                    ispLabel: ispMap[r.isp_type] || r.isp_type,
                    topN: r.top_n || 3,
                    enabled: !!r.enabled
                }));
                return Response.json({ success: true, baseDomain: env.CF_DOMAIN, subs: data });
            } catch(e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // 保存子域名调度配置
        if (url.pathname === '/api/subdomain-config' && request.method === 'POST') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定数据库' });
            try {
                await initDatabase(env);
                const body = await request.json();
                const subs = body.subs || [];
                for (const s of subs) {
                    if (!s.sub) continue;
                    const ispType = s.isp_type || '移动';
                    const topN = parseInt(s.top_n || 3);
                    const enabled = s.enabled ? 1 : 0;
                    await env.DB.prepare(
                        `INSERT OR REPLACE INTO dns_subdomain_config (sub, isp_type, top_n, enabled, updated_at) VALUES (?, ?, ?, ?, datetime('now', '+8 hours'))`
                    ).bind(s.sub, ispType, topN, enabled).run();
                }
                return Response.json({ success: true, message: '子域名配置已保存' });
            } catch(e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // 立即执行子域名调度（body.sub 指定单个，或不传则全部）
        if (url.pathname === '/api/subdomain-update' && request.method === 'POST') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定数据库' });
            try {
                await initDatabase(env);
                const body = await request.json().catch(() => ({}));
                const targetSub = body.sub || null;
                if (targetSub) {
                    // 单子域：直接在当前调用内执行（子请求数在免费账户 50 上限内）
                    const row = await env.DB.prepare('SELECT sub, isp_type, top_n, enabled FROM dns_subdomain_config WHERE sub = ?').bind(targetSub).first();
                    if (!row) return Response.json({ success: false, error: '子域不存在: ' + targetSub });
                    if (!row.enabled) return Response.json({ success: true, results: [{ sub: targetSub, enabled: false, skipped: true }] });
                    const subBase = (env.CF_DOMAIN || '').split('.').slice(1).join('.') || env.CF_DOMAIN;
                    const res = await runISPDnsUpdate(env, { domain: targetSub + '.' + subBase, ispType: row.isp_type, topN: row.top_n, triggerType: 'manual-sub', sub: targetSub });
                    res.sub = targetSub;
                    return Response.json({ success: true, results: [res] });
                }
                // 全部：逐子域自调用分发，避免单调用子请求超限
                return Response.json(await autoUpdateAllSubdomains(env));
            } catch(e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // 各子域当前优选 IP（供客户端本地 hosts/智能DNS 覆盖提速）
        if (url.pathname === '/api/best-ips' && request.method === 'GET') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定数据库' });
            try {
                await initDatabase(env);
                const subs = ['yd', 'lt', 'dx'];
                const out = {};
                for (const sub of subs) {
                    const row = await env.DB.prepare('SELECT nodes_json, created_at FROM dns_update_history WHERE sub = ? ORDER BY created_at DESC LIMIT 1').bind(sub).first();
                    if (row && row.nodes_json) {
                        let nodes = [];
                        try { nodes = JSON.parse(row.nodes_json); } catch (e) {}
                        out[sub] = { ips: nodes.map(n => n.ip), updated_at: row.created_at };
                    } else {
                        out[sub] = { ips: [], updated_at: null };
                    }
                }
                return Response.json({ success: true, baseDomain: env.CF_DOMAIN, best: out });
            } catch (e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // ASN 智能调度页：根据访问者运营商自动跳转到对应子域名
        if (url.pathname === '/go') {
            const cf = request.cf || {};
            const isp = detectISPFromCF(cf);
            const base = env.CF_DOMAIN;
            // 子域用一级域名（被 *.erebus.de5.net 证书与路由覆盖，免费套餐可用）；主域名保留 fandai.erebus.de5.net
            const subBase = (env.CF_DOMAIN || '').split('.').slice(1).join('.') || env.CF_DOMAIN;
            const subMap = { '移动': 'yd', '联通': 'lt', '电信': 'dx' };
            const targetSub = isp ? subMap[isp] : null;
            const ispCn = isp || '未知/海外';
            const links = [
                { sub: 'yd', label: '🟢 移动 yd', isp: '移动' },
                { sub: 'lt', label: '🟠 联通 lt', isp: '联通' },
                { sub: 'dx', label: '🔵 电信 dx', isp: '电信' }
            ];
            // 读取各子域当前优选 IP（供客户端本地 hosts 覆盖提速）
            let bestIps = {};
            try {
                for (const l of links) {
                    const row = await env.DB.prepare('SELECT nodes_json FROM dns_update_history WHERE sub = ? ORDER BY created_at DESC LIMIT 1').bind(l.sub).first();
                    if (row && row.nodes_json) { try { bestIps[l.sub] = JSON.parse(row.nodes_json).map(n => n.ip); } catch (e) {} }
                }
            } catch (e) {}
            // 程序化请求（非浏览器）直接 302
            const ua = request.headers.get('User-Agent') || '';
            const accept = request.headers.get('Accept') || '';
            if (targetSub && (!accept.includes('text/html') || /\b(curl|python|go-http|okhttp|ExoPlayer|Infuse|Emby|MediaBrowser)\b/i.test(ua))) {
                return Response.redirect(`https://${targetSub}.${subBase}/`, 302);
            }
            const linkHtml = links.map(l => {
                const ips = bestIps[l.sub] || [];
                const ipText = ips.length ? ips.join('、') : '（尚未调度，去面板点「全部调度」）';
                return `<div style="padding:12px 16px;margin:8px 0;border-radius:10px;border:1px solid var(--border);${l.isp===isp?'background:rgba(34,197,94,0.12);border-color:var(--success);':''}">
    <div style="font-weight:700;"><a href="https://${l.sub}.${subBase}/" style="color:var(--text);text-decoration:none;">${l.label}.${subBase}</a> ${l.isp===isp?'← 检测到您的网络':''}</div>
    <div style="font-size:12px;color:#9ca3af;margin-top:6px;">优选IP：<code>${ipText}</code> <button class="cp" data-copy="${ips.join(',')}">复制</button></div>
  </div>`;
            }).join('');
            const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>智能反代系统 · 线路选择</title>
<style>body{font-family:system-ui,-apple-system,'PingFang SC',sans-serif;background:radial-gradient(800px 400px at 50% -10%,#0f3d2e,#0b1120);color:#e5e7eb;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0;padding:20px;} .box{max-width:480px;width:100%;} h2{margin:0 0 6px;} .sub{color:#9ca3af;font-size:13px;margin-bottom:18px;} code{background:rgba(120,120,120,.15);padding:2px 6px;border-radius:6px;word-break:break-all;} .cp{margin-left:8px;background:#1a2433;color:#e5e7eb;border:1px solid #243140;border-radius:6px;padding:2px 8px;font-size:12px;cursor:pointer;} .cp:hover{background:#243140;}</style>
${targetSub?`<meta http-equiv="refresh" content="2;url=https://${targetSub}.${subBase}/">`:''}
</head><body><div class="box">
<h2>🌐 智能反代系统 · 线路选择</h2>
<div class="sub">检测到您的网络：<b>${ispCn}</b><br>2 秒后将自动跳转至最优线路；也可手动选择：</div>
${linkHtml}
<div class="sub" style="margin-top:18px;">把播放器/客户端的地址设为对应子域名即可走该运营商优选 IP。<br>主域名 <code>${base}</code> 仍按面板「智能DNS自动调度」配置生效。<br><b>提速：</b>在客户端本地 hosts / 智能DNS 中将子域名覆盖为上方「优选IP」，可走该运营商最快 Cloudflare 边缘。</div>
<script>document.addEventListener('click',function(e){var b=e.target.closest('.cp');if(b){var t=b.getAttribute('data-copy');if(t&&navigator.clipboard){navigator.clipboard.writeText(t).then(function(){b.textContent='已复制';setTimeout(function(){b.textContent='复制';},1500);});}}});</script>
</div></body></html>`;
            return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

        // ==========================================
        // 2.5 公开健康检查 API（供导航页显示源站状态）
        // ==========================================
        if (url.pathname === '/api/health' && request.method === 'GET') {
            if (!env.DB) return Response.json({ success: false, error: '未绑定 DB' });
            try {
                const { results } = await env.DB.prepare("SELECT prefix, target FROM routes ORDER BY sort_order").all();
                const checks = await Promise.all(results.map(async r => {
                    const target = String(r.target || '').split(',')[0].trim();
                    if (!target) return { prefix: r.prefix, online: false, error: '无目标地址' };
                    try {
                        const ctrl = new AbortController();
                        const timer = setTimeout(() => ctrl.abort(), 5000);
                        const res = await fetch(target, { method: 'GET', signal: ctrl.signal, redirect: 'follow' });
                        clearTimeout(timer);
                        return { prefix: r.prefix, online: res.status < 500, status: res.status };
                    } catch (e) {
                        return { prefix: r.prefix, online: false, error: e.name === 'AbortError' ? '超时' : '无法连接' };
                    }
                }));
                const out = {};
                for (const c of checks) out[c.prefix] = { online: c.online, status: c.status, error: c.error };
                return Response.json({ success: true, checks: out, time: new Date().toISOString() });
            } catch (e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // ==========================================
        // 2.6 数据库路由管理 API
        // ==========================================
        if (url.pathname === '/api/routes/reorder' && request.method === 'POST') {
            if (!env.DB) return Response.json({ success: false, error: "未绑定 DB" });
            try {
                const items = await request.json(); 
                const stmts = items.map(item => env.DB.prepare('UPDATE routes SET sort_order = ? WHERE prefix = ?').bind(item.sort_order, item.prefix));
                await env.DB.batch(stmts);
                return Response.json({ success: true });
            } catch (e) { return Response.json({ success: false, error: e.message }); }
        }

        if (url.pathname === '/api/routes/import' && request.method === 'POST') {
            if (!env.DB) return Response.json({ success: false, error: "未绑定 DB" });
            try {
                const routes = await request.json();
                for (const r of routes) {
                    if (r.prefix && r.target) {
                        await env.DB.prepare('INSERT OR REPLACE INTO routes (prefix, target, mode, remark, last_play, icon, cache_img, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
                            .bind(r.prefix, r.target, r.mode || 'off', r.remark || '', r.last_play || '', r.icon || '', r.cache_img || 'on', r.sort_order || 0).run();
                    }
                }
                return Response.json({ success: true });
            } catch (e) { return Response.json({ success: false, error: e.message }); }
        }

        if (url.pathname.startsWith('/api/routes')) {
            if (!env.DB) return Response.json({ error: "由于未绑定 D1 数据库，反代功能不可用。" }, { status: 500 });

            await env.DB.exec(`CREATE TABLE IF NOT EXISTS routes (prefix TEXT PRIMARY KEY, target TEXT NOT NULL)`);
            await env.DB.exec(`CREATE TABLE IF NOT EXISTS request_stats (prefix TEXT, date TEXT, count INTEGER DEFAULT 0, PRIMARY KEY(prefix, date))`);
            // 🚀 节点今日流量缓存表：避免每次刷新都打 CF GraphQL，兼顾速度与实时
            await env.DB.exec(`CREATE TABLE IF NOT EXISTS route_bandwidth (prefix TEXT, date TEXT, bytes INTEGER DEFAULT 0, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(prefix, date))`);
            // 大数据记录核心表：访客日志
            await env.DB.exec(`CREATE TABLE IF NOT EXISTS visitor_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, ip TEXT, country TEXT, ua TEXT)`);
            
            try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN mode TEXT DEFAULT 'off'`); } catch(e) {}
            try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN remark TEXT DEFAULT ''`); } catch(e) {}
            try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN last_play TEXT DEFAULT ''`); } catch(e) {}
            try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN icon TEXT DEFAULT ''`); } catch(e) {}
            try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN cache_img TEXT DEFAULT 'on'`); } catch(e) {} 
            try { await env.DB.exec(`ALTER TABLE routes ADD COLUMN sort_order INTEGER DEFAULT 0`); } catch(e) {} 
            
            // 智能DNS自动调度 - 新增表
            try { await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_update_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nodes_json TEXT DEFAULT '[]',
                trigger_type TEXT DEFAULT 'auto',
                total_tested INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                error_msg TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`); } catch(e) { console.log("dns_update_history table creation error:", e.message); }
            try { await env.DB.exec(`CREATE TABLE IF NOT EXISTS dns_node_history (
                node_ip TEXT PRIMARY KEY,
                total_count INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                avg_latency INTEGER DEFAULT 0,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )`); } catch(e) { console.log("dns_node_history table creation error:", e.message); }

            // Bot推送配置表
            try { await env.DB.exec(`CREATE TABLE IF NOT EXISTS bot_config (
                id INTEGER PRIMARY KEY DEFAULT 1,
                bot_enabled INTEGER DEFAULT 1,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`); } catch(e) { console.log("bot_config table creation error:", e.message); }
            try { await env.DB.prepare(`INSERT OR IGNORE INTO bot_config (id, bot_enabled) VALUES (1, 1)`).run(); } catch(e) {}

            // 清理30天前的历史记录
            try { await env.DB.exec(`DELETE FROM dns_update_history WHERE created_at < datetime('now', '-30 days')`); } catch(e) {}
            try { await env.DB.exec(`DELETE FROM dns_node_history WHERE last_seen < datetime('now', '-30 days')`); } catch(e) {}

            // 数据防爆清理策略：自动清理过去 7 天的精细日志
            try { await env.DB.exec(`DELETE FROM visitor_logs WHERE timestamp < datetime('now', '-7 days')`); } catch(e) {}

            // 🚀 首屏即时返回（流量走 D1 缓存），后台并发刷新 CF GraphQL 流量缓存
            if (request.method === 'GET') {
                try {
                const todayStr = new Date(Date.now() + 8 * 3600000).toISOString().split('T')[0];
                const { results: routes } = await env.DB.prepare(`
                    SELECT r.*, 
                    IFNULL(s.count, 0) as todayReqs,
                    (SELECT SUM(count) FROM request_stats WHERE prefix = r.prefix) as totalReqs,
                    IFNULL(b.bytes, 0) as todayBytes
                    FROM routes r 
                    LEFT JOIN request_stats s ON r.prefix = s.prefix AND s.date = ? 
                    LEFT JOIN route_bandwidth b ON r.prefix = b.prefix AND b.date = ? 
                    ORDER BY r.sort_order ASC, r.prefix ASC
                `).bind(todayStr, todayStr).all();

                // 用 D1 缓存的字节数直接给出今日流量（首屏即时渲染，不阻塞）
                (routes || []).forEach(r => { r.todayBandwidth = formatBytes(r.todayBytes || 0); });

                // 后台刷新今日流量缓存：并发向 CF GraphQL 拉取各节点精准流量并写回 D1
                if (env.CF_API_TOKEN && env.CF_ZONE_ID && routes && routes.length > 0) {
                    const prefixes = routes.map(r => r.prefix);
                    ctx.waitUntil(refreshRouteBandwidth(env, prefixes, todayStr));
                }
                
                return Response.json(routes || []);
                } catch (error) {
                    console.error("Error in /api/routes GET:", error);
                    return Response.json({ error: "数据库查询失败: " + error.message }, { status: 500 });
                }
            }
            
            if (request.method === 'POST') {
                try {
                    const data = await request.json();
                    let currentSortOrder = 0;
                    
                    // ========== 输入验证 ==========
                    if (!data.prefix || !data.target) {
                        return Response.json({ 
                            success: false, 
                            error: '缺少必要参数: prefix 和 target' 
                        }, { status: 400 });
                    }
                    
                    // 验证 prefix - 防止路径遍历
                    const prefix = String(data.prefix).trim();
                    if (!prefix || prefix.includes('/') || prefix.includes('\\') || prefix.includes('..') || prefix.length > 100) {
                        return Response.json({ 
                            success: false, 
                            error: 'prefix 不能包含路径分隔符，长度不能超过 100 字符' 
                        }, { status: 400 });
                    }
                    
                    // 验证 target URL
                    const targetStr = String(data.target).trim();
                    const targetUrls = targetStr.split(',').map(s => s.trim()).filter(Boolean);
                    for (const u of targetUrls) {
                        if (!isValidUrl(u)) {
                            return Response.json({ 
                                success: false, 
                                error: '无效的目标 URL 格式，请确保使用 http:// 或 https://' 
                            }, { status: 400 });
                        }
                    }
                    
                    // 验证 oldPrefix (如果提供)
                    let oldPrefix = data.oldPrefix ? String(data.oldPrefix).trim() : null;
                    if (oldPrefix && (oldPrefix.includes('/') || oldPrefix.includes('\\') || oldPrefix.includes('..'))) {
                        return Response.json({ 
                            success: false, 
                            error: 'oldPrefix 格式无效' 
                        }, { status: 400 });
                    }
                    
                    // ========== 数据库操作 ==========
                    if (oldPrefix && oldPrefix !== prefix) {
                        const oldRow = await env.DB.prepare('SELECT sort_order FROM routes WHERE prefix = ?').bind(oldPrefix).first();
                        if(oldRow) currentSortOrder = oldRow.sort_order;
                        await env.DB.prepare('DELETE FROM routes WHERE prefix = ?').bind(oldPrefix).run();
                    } else {
                        const oldRow = await env.DB.prepare('SELECT sort_order FROM routes WHERE prefix = ?').bind(prefix).first();
                        if(oldRow) currentSortOrder = oldRow.sort_order;
                    }
                    
                    // 处理模式
                    const validModes = ['off', 'realip_only', 'dual', 'strict'];
                    const mode = validModes.includes(data.mode) ? data.mode : 'off';
                    
                    // 处理缓存设置
                    const cacheImg = (data.cache_img === 'on' || data.cache_img === 'off') ? data.cache_img : 'on';
                    
                    // 安全处理备注和图标
                    const remark = String(data.remark || '').substring(0, 200);
                    const icon = String(data.icon || '').substring(0, 500);
                    
                    await env.DB.prepare('INSERT OR REPLACE INTO routes (prefix, target, mode, remark, icon, cache_img, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)')
                        .bind(prefix, targetStr, mode, remark, icon, cacheImg, currentSortOrder).run();
                    return Response.json({ success: true });
                } catch (e) {
                    console.error('Error in /api/routes POST:', e);
                    return Response.json({ 
                        success: false, 
                        error: '服务器错误: ' + e.message 
                    }, { status: 500 });
                }
            }
            
            if (request.method === 'DELETE') {
                try {
                    const prefix = url.searchParams.get('prefix');
                    if (!prefix || prefix.includes('/') || prefix.includes('\\') || prefix.includes('..') || prefix.length > 100) {
                        return Response.json({ 
                            success: false, 
                            error: '无效的 prefix 参数' 
                        }, { status: 400 });
                    }
                    await env.DB.prepare('DELETE FROM routes WHERE prefix = ?').bind(prefix).run();
                    return Response.json({ success: true });
                } catch (e) {
                    console.error('Error in /api/routes DELETE:', e);
                    return Response.json({ 
                        success: false, 
                        error: '服务器错误: ' + e.message 
                    }, { status: 500 });
                }
            }
            return new Response("Method not allowed", { status: 405 });
        }

        // ==========================================
        // 🌟 优选域名测速接口（借鉴 EMBY_CF：边缘测速 + 按客户端网段缓存 1 小时）
        // GET：优先读缓存，无缓存则边缘测速并写回；POST：接收浏览器端复测结果并缓存
        // ==========================================
        if (url.pathname === '/api/domains/speed') {
            try {
                const clientIp = request.headers.get('cf-connecting-ip') || request.headers.get('x-real-ip') || '0.0.0.0';
                const cacheKey = getClientCacheKey(clientIp);

                if (request.method === 'POST') {
                    const body = await request.json().catch(() => ({}));
                    if (body && Array.isArray(body.results) && body.results.length) {
                        const sorted = body.results.slice().sort((a, b) => (a.ms == null ? 9999 : a.ms) - (b.ms == null ? 9999 : b.ms));
                        try {
                            await env.DB.prepare('INSERT OR REPLACE INTO domain_speed_cache (cache_key, results_json, ts) VALUES (?, ?, ?)')
                                .bind(cacheKey, JSON.stringify(sorted), Date.now()).run();
                        } catch (e) {}
                        return Response.json({ success: true, best: sorted[0] && sorted[0].host ? sorted[0].host : null });
                    }
                    return Response.json({ success: false, error: '无效结果' });
                }

                // GET
                let cached = null;
                try {
                    cached = await env.DB.prepare('SELECT results_json, ts FROM domain_speed_cache WHERE cache_key = ?').bind(cacheKey).first();
                } catch (e) {}
                const HOUR = 3600 * 1000;
                if (cached && cached.ts && (Date.now() - cached.ts) < HOUR) {
                    const results = JSON.parse(cached.results_json || '[]');
                    return Response.json({ success: true, cached: true, results, best: results[0] && results[0].host ? results[0].host : null });
                }
                const results = await speedtestOptimizedFromEdge();
                try {
                    await env.DB.prepare('INSERT OR REPLACE INTO domain_speed_cache (cache_key, results_json, ts) VALUES (?, ?, ?)')
                        .bind(cacheKey, JSON.stringify(results), Date.now()).run();
                } catch (e) {}
                return Response.json({ success: true, cached: false, results, best: results[0] && results[0].host ? results[0].host : null });
            } catch (e) {
                return Response.json({ success: false, error: e.message });
            }
        }

        // ==========================================
        // 2.6 核心反代与调度引擎
        // ==========================================
        let targetUrls = []; let currentMode = 'off'; let enableCache = true; let remainingPath = '';
        const decodedPath = decodeURIComponent(url.pathname); let matchedPrefix = null; 
        const requestUrl = new URL(request.url);
        let proxyOrigin = requestUrl.origin;
        // 子域请求（如 dx.erebus.de5.net）归一化标识：host 属于本 zone（erebus.de5.net）但不是主域本身。
        // 注意：一级子域 dx.erebus.de5.net 并不以主域 fandai.erebus.de5.net 结尾，故用 zone 根域判定。
        const zoneRoot = env.CF_DOMAIN.split('.').slice(1).join('.');
        const isSubDomainRequest = requestUrl.host !== env.CF_DOMAIN && requestUrl.host.endsWith('.' + zoneRoot);
        // 媒体流 URL 重写统一指向主域：子域灰云记录的证书在媒体分片/并行请求下不稳定（面板正常但媒体报 TLS 错误），
        // 而主域 fandai.erebus.de5.net 的反代媒体已验证可用，故媒体始终走主域，绕开子域 TLS 问题
        const mediaProxyOrigin = 'https://' + env.CF_DOMAIN;

        if (decodedPath.startsWith('/http://') || decodedPath.startsWith('/https://')) {
            targetUrls = [decodedPath.substring(1)]; remainingPath = '';
        } else {
            const pathParts = decodedPath.split('/'); const prefix = pathParts[1]; 
            if (!prefix) return new Response(`Not Found`, { status: 404 });

            try {
                if (!env.DB) return new Response(`404: Node not found (DB not bound)`, { status: 404 });
                const stmt = env.DB.prepare(`SELECT target, mode, cache_img FROM routes WHERE prefix = ?`);
                const route = await stmt.bind(prefix).first();
                if (!route) return new Response(`404: Node not found`, { status: 404 });

                currentMode = route.mode || 'off'; enableCache = (route.cache_img !== 'off');
                matchedPrefix = prefix; remainingPath = '/' + pathParts.slice(2).join('/');
                targetUrls = route.target.split(',').map(s => s.trim()).filter(Boolean);
                
                if (remainingPath.startsWith('/http://') || remainingPath.startsWith('/https://')) { targetUrls = [remainingPath.substring(1)]; remainingPath = ''; }
            } catch (e) { return new Response("DB Error: " + e.message, { status: 500 }); }
        }

        if (targetUrls.length === 0) return new Response("404: Target empty", { status: 404 });

        // ==========================================
        // 2.7 防爆型精准日志拦截 (修复统计虚高：仅拦截点火请求)
        // ==========================================
        // 检测播放相关请求：PlaybackInfo、播放列表、视频流请求
        const isPlayRequest = /\/PlaybackInfo|\/playbackinfo|\.m3u8|\.mp4|\.mkv|\.ts(\?|$)|.m4s|\.webm|\/stream(\?|$)|video\.mp4/i.test(url.pathname + url.search);
        const isDashboardRequest = url.pathname === '/' || url.pathname === '/web/index.html';

        // 更新最后活跃时间：只要有任何请求就更新（包括访问首页、播放请求等）
        if (matchedPrefix && env.DB && ctx && ctx.waitUntil) {
            try {
                const nowTime = new Date(Date.now() + 8 * 3600000).toISOString().replace('T', ' ').split('.')[0];
                ctx.waitUntil(env.DB.prepare(`UPDATE routes SET last_play = ? WHERE prefix = ?`).bind(nowTime, matchedPrefix).run());
            } catch(e) {}
        }

        // 核心修改：仅在点火请求时才记录 "今日播放" 和访客日志
        if (isPlayRequest && matchedPrefix && env.DB && ctx && ctx.waitUntil) {
            try {
                const todayStr = new Date(Date.now() + 8 * 3600000).toISOString().split('T')[0];
                
                let stmts = [
                    env.DB.prepare(`INSERT INTO request_stats (prefix, date, count) VALUES (?, ?, 1) ON CONFLICT(prefix, date) DO UPDATE SET count = count + 1`).bind(matchedPrefix, todayStr)
                ];

                const clientIp = request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip") || "Unknown";
                const clientCountry = request.headers.get("cf-ipcountry") || "Unknown";
                const clientUa = request.headers.get("User-Agent") || "Unknown";
                const cfGeo = request.cf || {};
                const clientLat = parseFloat(cfGeo.latitude) || 0;
                const clientLon = parseFloat(cfGeo.longitude) || 0;
                const clientCity = cfGeo.city || '';
                stmts.push(env.DB.prepare(`INSERT INTO visitor_logs (prefix, ip, country, ua, lat, lon, city) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(matchedPrefix, clientIp, clientCountry, clientUa, clientLat, clientLon, clientCity));

                ctx.waitUntil(env.DB.batch(stmts));
            } catch(e) {}
        }

        // ==========================================
        // 2.8 无伪装模式下的源站反代 (含强力防 403 引擎)
        // ==========================================
        const isStrictMode = currentMode === 'strict';

        let bodyBuffer = null;
        if (request.method !== 'GET' && request.method !== 'HEAD' && targetUrls.length > 1) {
            bodyBuffer = await request.clone().arrayBuffer();
        }

        let finalResponse = null; let lastError = null;
        const foEnabled = (env.DB) ? (await getCfg(env, 'failover_enabled', 'on') === 'on') : true;

        // 尝试所有节点（含运行时故障转移）
        for (let i = 0; i < targetUrls.length; i++) {
            const targetUrlStr = targetUrls[i] + remainingPath + url.search; const targetUrl = new URL(targetUrlStr);

            // 🔀 运行时故障转移：已知近期不可用的节点直接跳过（除非是最后一个兜底）
            if (foEnabled && targetUrls.length > 1 && i < targetUrls.length - 1 && isNodeDown(targetUrlStr)) {
                lastError = new Error(`节点 ${i+1} 近期不可用，已跳过`); continue;
            }

            const newHeaders = new Headers(request.headers); newHeaders.set("Host", targetUrl.host);

            const realIp = request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip") || (request.headers.get("x-forwarded-for") || "").split(',')[0].trim();
            newHeaders.delete("cf-connecting-ip"); newHeaders.delete("cf-ipcountry"); newHeaders.delete("cf-ray");
            newHeaders.delete("cf-visitor"); newHeaders.delete("x-forwarded-for"); newHeaders.delete("x-real-ip");

            if (currentMode === 'realip_only' && realIp) { newHeaders.set("X-Real-IP", realIp); } 
            else if (currentMode === 'dual' && realIp) { newHeaders.set("X-Real-IP", realIp); newHeaders.set("X-Forwarded-For", realIp); }
            else if (isStrictMode) {
                // 强力防 403 模式：强制清空原始端代理参数，对齐 Origin
                newHeaders.delete("X-Forwarded-Proto"); newHeaders.delete("X-Forwarded-Host");
                newHeaders.set("Origin", targetUrl.origin); newHeaders.set("Referer", targetUrl.origin + "/");
                if (realIp) { newHeaders.set("X-Real-IP", realIp); newHeaders.set("X-Forwarded-For", realIp); }
            }

            // 子域请求（dx/lt/yd.erebus.de5.net）：非 strict 模式下，把 Origin/Referer 归一化为主域，
            // 使上游看到的来源与主域请求一致（主域已知可用），消除子域特有的防 403 / 防盗链拦截
            if (isSubDomainRequest && !isStrictMode) {
                const mainOrigin = 'https://' + env.CF_DOMAIN;
                newHeaders.set("Origin", mainOrigin);
                newHeaders.set("Referer", mainOrigin + "/");
                newHeaders.set("X-Forwarded-Host", env.CF_DOMAIN);
            }

            const isStaticOrImage = /\.(jpg|jpeg|gif|png|svg|ico|webp|js|css|woff2?|ttf|otf|map|webmanifest|srt|ass|vtt|sub)$/i.test(targetUrl.pathname) || /(\/Images\/|\/Icons\/|\/Branding\/|\/emby\/covers\/)/i.test(targetUrl.pathname);

            let fetchInit = { method: request.method, headers: newHeaders, redirect: 'manual' };

            if (isStaticOrImage && enableCache) { fetchInit.cf = { cacheEverything: true, cacheTtl: 86400 }; }

            if (request.method !== 'GET' && request.method !== 'HEAD') {
                if (targetUrls.length > 1) { fetchInit.body = bodyBuffer; } 
                else { fetchInit.body = request.body; fetchInit.duplex = 'half'; }
            }

            try {
                const modifiedRequest = new Request(targetUrl, fetchInit); const response = await fetch(modifiedRequest);
                // 5xx（含 502/503/504/520-524 等 Cloudflare 错误码）视为节点故障，触发故障转移
                if (response.status >= 500) {
                    lastError = new Error(`节点 ${i+1} 返回 HTTP ${response.status}`);
                    if (foEnabled && env.DB) {
                        markNodeDown(targetUrlStr);
                        if (i < targetUrls.length - 1) ctx.waitUntil(logFailover(env, matchedPrefix, targetUrlStr, 'HTTP ' + response.status));
                    }
                    continue;
                }
                markNodeUp(targetUrlStr);
                finalResponse = response; break; 
            } catch (err) {
                lastError = err;
                if (foEnabled && env.DB) {
                    markNodeDown(targetUrlStr);
                    if (i < targetUrls.length - 1) ctx.waitUntil(logFailover(env, matchedPrefix, targetUrlStr, '连接失败:' + (err.name || err.message)));
                }
                continue;
            }
        }

        if (!finalResponse) return new Response("Worker Proxy Failover Exhausted. All nodes failed. Last Error: " + (lastError?.message || 'Unknown Error'), { status: 502 });

        const responseHeaders = new Headers(finalResponse.headers);
        
        // 统一前缀变量，确保绝对安全，不会抛出未定义错误
        // 假设你前面获取路由节点的变量叫 matchedPrefix，如果有值就带上斜杠
        const safePrefix = matchedPrefix ? `/${matchedPrefix}` : '';

        // ==========================================
        // 🚀 修复版 302 拦截：恢复 URL 编码
        // ==========================================
        if ([301, 302, 303, 307, 308].includes(finalResponse.status)) {
            const location = responseHeaders.get('Location');
            if (location && /^https?:\/\//i.test(location)) {
                // 🎯 补回 encodeURIComponent，防止播放器解析重定向头时发疯
                responseHeaders.set('Location', `${safePrefix}/${encodeURIComponent(location)}`);
            }
        }
        
        responseHeaders.set('Access-Control-Allow-Origin', '*');

        // ==========================================
        // 2.10 响应体重写 (接管 PlaybackInfo 与 M3U8)
        // ==========================================

        if (finalResponse.status === 200 && responseHeaders.get("content-type")?.includes("json") && url.pathname.toLowerCase().includes("playbackinfo")) {
            try {
                let clonedRes = finalResponse.clone(); 
                let data = await clonedRes.json(); 
                let modified = false;
                if (data && data.MediaSources) {
                    data.MediaSources.forEach(source => {
                        ['DirectStreamUrl', 'TranscodingUrl'].forEach(key => {
                            if (source[key] && source[key].startsWith('http')) { 
                                // 🎯 统一使用 safePrefix，杜绝 ReferenceError 导致重写崩溃；媒体 URL 统一指向主域
                                source[key] = mediaProxyOrigin + safePrefix + '/' + source[key]; 
                                modified = true; 
                            }
                        });
                    });
                }
                if (modified) { 
                    responseHeaders.delete("Content-Length"); 
                    return new Response(JSON.stringify(data), { status: finalResponse.status, statusText: finalResponse.statusText, headers: responseHeaders }); 
                }
            } catch (e) {
                // 别再隐式吞报错了，如果出问题，可以在 Worker 日志里看得到
                console.log("PlaybackInfo JSON 重写失败:", e.message);
            }
        }

        // 🚀 处理 M3U8 播放列表中的真实视频切片链接
        if (finalResponse.status === 200 && url.pathname.toLowerCase().endsWith('.m3u8')) {
            try {
                let clonedRes = finalResponse.clone(); 
                let text = await clonedRes.text();
                if (text.includes('http://') || text.includes('https://')) {
                    // 🎯 同样修复变量名
                    let modifiedText = text.replace(/(https?:\/\/[^\s]+)/g, mediaProxyOrigin + safePrefix + '/$1');
                    responseHeaders.delete("Content-Length"); 
                    return new Response(modifiedText, { status: finalResponse.status, statusText: finalResponse.statusText, headers: responseHeaders });
                }
            } catch(e) {
                console.log("M3U8 重写失败:", e.message);
            }
        }

        // 静态资源缓存控制保持不变
        const isStaticRes = /\.(jpg|jpeg|gif|png|svg|ico|webp|js|css|woff2?|ttf|otf|map|webmanifest|srt|ass|vtt|sub)$/i.test(url.pathname) || /(\/Images\/|\/Icons\/|\/Branding\/|\/emby\/covers\/)/i.test(url.pathname);
        if (isStaticRes && enableCache) {
            responseHeaders.set('Cache-Control', 'public, max-age=86400'); 
            responseHeaders.delete('Expires'); 
            responseHeaders.delete('Pragma');  
        } else { 
            responseHeaders.set('Cache-Control', 'no-store'); 
        }

        return new Response(finalResponse.body, { status: finalResponse.status, statusText: finalResponse.statusText, headers: responseHeaders });
        } catch (error) {
            console.error("Worker error:", error);
            return new Response(JSON.stringify({ error: error.message, stack: error.stack }), { status: 500, headers: { 'Content-Type': 'application/json' } });
        }
    }
};