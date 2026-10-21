/* FabriTrade — real marketplace server (v2)
 * Pure Node.js, no npm install needed.   Run:  node server.js
 * - Accounts (first account created becomes the OWNER), listings, orders + escrow + commission,
 *   RFQs & offers, messaging with AI scam-flagging, boosts, samples, platform settings,
 *   and a private owner/admin API used by the Manager site.
 * - Data lives in data.json (swap for a database later without changing the API).
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
// On Render with a persistent disk, set DATA_DIR=/var/data so data survives restarts and deploys.
const DATA_DIR = process.env.DATA_DIR || __dirname;
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
const DATA_FILE = path.join(DATA_DIR, "data.json");
// Optional: OWNER_EMAIL locks platform ownership to this email (recommended).
const OWNER_EMAIL = (process.env.OWNER_EMAIL || "").toLowerCase().trim();
const PUBLIC = path.join(__dirname, "public");

/* ---------- database ----------
   Storage, in order of preference:
   1) Upstash Redis (free cloud database) — set UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN.
      Survives restarts even on Render's FREE plan.
   2) A local file data.json (in DATA_DIR) — survives restarts only with a persistent disk. */
const UP_URL = (process.env.UPSTASH_REDIS_REST_URL || "").replace(/\/$/, "");
const UP_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const UP_KEY = process.env.UPSTASH_KEY || "fabritrade:db";
const USE_UPSTASH = !!(UP_URL && UP_TOKEN);
async function upstash(cmd){
  const r = await fetch(UP_URL, { method:"POST", headers:{ Authorization:"Bearer " + UP_TOKEN, "Content-Type":"application/json" }, body: JSON.stringify(cmd) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error("Upstash: " + (j.error || r.status));
  return j.result;
}
let db;
function loadFile(){ try { return JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); } catch { return null; } }
let cloudTimer = null, cloudDirty = false, cloudBusy = false;
async function pushCloud(){
  if (cloudBusy) { cloudDirty = true; return; }
  cloudBusy = true; cloudDirty = false;
  try { await upstash(["SET", UP_KEY, JSON.stringify(db)]); }
  catch (e) { console.error("Cloud save failed, will retry:", e.message); cloudDirty = true; }
  cloudBusy = false;
  if (cloudDirty) { clearTimeout(cloudTimer); cloudTimer = setTimeout(pushCloud, 1500); }
}
function saveDB(){
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(db)); } catch {}
  if (USE_UPSTASH) { clearTimeout(cloudTimer); cloudTimer = setTimeout(pushCloud, 300); }
}
async function initDB(){
  if (USE_UPSTASH) {
    try { const raw = await upstash(["GET", UP_KEY]); if (raw) db = JSON.parse(raw); console.log("Loaded data from Upstash:", db ? "yes" : "empty"); }
    catch (e) { console.error("Could not reach Upstash:", e.message); }
  }
  if (!db) db = loadFile();
  if (!db) {
    db = {
      secret: crypto.randomBytes(32).toString("hex"),
      seq: { user:0, listing:0, order:0, message:0, rfq:0, flag:0 },
      settings: { commission:3.5, boostFee:9.99, sampleFee:5, requireVerify:false, maintenance:false, announcement:"", autoFlag:true, prelaunch:true, launchText:"2027" },
      revenue: { commission:0, boosts:0 },
      users:[], listings:[], orders:[], messages:[], rfqs:[], flags:[], log:[],
    };
    seed();
  }
  // backfill for older data
  db.settings = Object.assign({ commission:3.5, boostFee:9.99, sampleFee:5, requireVerify:false, maintenance:false, announcement:"", autoFlag:true, prelaunch:true, launchText:"2027" }, db.settings||{});
  db.revenue = db.revenue || { commission:0, boosts:0 };
  ["rfqs","flags","log","waitlist","swatches","submissions"].forEach(k=>{ if(!Array.isArray(db[k])) db[k]=[]; });
  if (!db.stats || typeof db.stats !== "object") db.stats = {};
  ["rfq","flag"].forEach(k=>{ if(!db.seq[k]) db.seq[k]=0; });
  saveDB();
}

function nextId(k){ return (db.seq[k] = (db.seq[k]||0) + 1); }
function now(){ return Date.now(); }
function COMM(){ return (+db.settings.commission || 3.5) / 100; }
function logAdmin(msg){ db.log.unshift({ t: now(), m: msg }); db.log = db.log.slice(0, 300); }

/* ---------- auth helpers ---------- */
function hashPassword(password, salt){ salt = salt || crypto.randomBytes(16).toString("hex"); return { salt, hash: crypto.scryptSync(password, salt, 64).toString("hex") }; }
function checkPassword(p, salt, hash){ try { return crypto.timingSafeEqual(Buffer.from(crypto.scryptSync(p, salt, 64).toString("hex")), Buffer.from(hash)); } catch { return false; } }
/* Login tokens: signed, expire after 30 days, and stop working if the password changes (tokenVer bumps). */
const TOKEN_DAYS = 30, ADMIN_HOURS = 12;
function makeToken(id){ const u = db.users.find(x => x.id === id); const body = id + "." + now() + "." + ((u && u.tokenVer) || 0); const sig = crypto.createHmac("sha256", db.secret).update(body).digest("hex"); return Buffer.from(body + "." + sig).toString("base64"); }
function readToken(tok){
  try {
    const parts = Buffer.from(String(tok || ""), "base64").toString("utf8").split(".");
    let id, ts, ver, sig;
    if (parts.length === 4) [id, ts, ver, sig] = parts; else if (parts.length === 3) { [id, ts, sig] = parts; ver = null; } else return null; // 3 parts = older login, still honoured until it expires
    const body = ver === null ? id + "." + ts : id + "." + ts + "." + ver;
    const good = crypto.createHmac("sha256", db.secret).update(body).digest("hex");
    if (good.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(good), Buffer.from(sig))) return null;
    if (now() - +ts > TOKEN_DAYS * 864e5 || +ts > now() + 6e4) return null;
    const u = db.users.find(x => x.id === +id); if (!u) return null;
    if ((+ver || 0) !== (u.tokenVer || 0)) return null;
    return { user: u, age: now() - +ts };
  } catch { return null; }
}
function userFromToken(tok){ const r = readToken(tok); return r ? r.user : null; }
// pub = what a user sees about THEMSELVES (and the owner sees in the Manager). others = what other users may see (no email).
const pub = u => u && ({ id:u.id, name:u.name, email:u.email, role:u.role, verified:!!u.verified, suspended:!!u.suspended, country:u.country||"" });
const publicUser = u => u && ({ id:u.id, name:u.name, role:u.role === "owner" ? "seller" : u.role, verified:!!u.verified, founding:!!u.founding, country:u.country||"" });

/* ---------- http helpers ---------- */
function cors(res){ res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization"); res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS"); }
function send(res, code, obj){ cors(res); res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); }
function body(req){ return new Promise(r => { let d = ""; req.on("data", c => { d += c; if (d.length > 8e6) req.destroy(); }); req.on("end", () => { try { r(d ? JSON.parse(d) : {}); } catch { r({}); } }); }); }
function bearer(req){ return (req.headers["authorization"]||"").replace(/^Bearer\s+/i, ""); }
function auth(req){ const u = userFromToken(bearer(req)); return u && !u.suspended ? u : null; }
function listingOut(l){ const s = db.users.find(u => u.id === l.ownerId); return { ...l, rating: undefined, sellerName: l.displaySeller || (s ? s.name : "Unknown"), sellerVerified: l.displaySeller ? !!l.displayVerified : !!(s && s.verified), sellerFounding: l.displaySeller ? true : !!(s && s.founding), trades: db.orders.filter(o => o.sellerId === l.ownerId && o.status !== "refunded").length }; }

/* ---------- AI scam flagging (rule-based; swap for an AI API later) ---------- */
const RISKY = ["bank wire","bank transfer","wire transfer","western union","whatsapp","wechat","telegram","zalo","paypal","off platform","off-platform","offline","skip the fee","skip the platform","account number","iban","转账","银行","线下","微信","私下","chuyển khoản","ngoài nền tảng","ngân hàng"];
function riskReason(text){
  const s = String(text).toLowerCase(); const hit = RISKY.find(w => s.includes(w));
  if (hit) return "Off-platform payment / contact attempt (\"" + hit + "\")";
  if (/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(s)) return "Shared an email address (off-platform contact)";
  if ((s.match(/\+?\d[\d\s().-]{7,}\d/g) || []).some(x => x.replace(/\D/g, "").length >= 9)) return "Shared a phone number (off-platform contact)";
  return null;
}
/* waitlist helpers */
const wlHits = new Map();
function wlAllowed(ip){ const t = now(), arr = (wlHits.get(ip) || []).filter(x => t - x < 3600e3); if (arr.length >= 10) return false; arr.push(t); wlHits.set(ip, arr); return true; }
function unsubToken(email){ return crypto.createHmac("sha256", db.secret).update("unsub:" + email).digest("hex").slice(0, 24); }
const PUBLIC_URL = (process.env.PUBLIC_URL || "https://fabritrade-server.onrender.com").replace(/\/$/, "");
/* ================= email (Resend), images (Cloudinary), visitor counts =================
   Optional settings on Render:
     RESEND_API_KEY, MAIL_FROM ("FabriTrade <support@fabritrade.net>"), APP_URL (https://fabritrade.net/app.html)
     CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
   Without them everything still works: emails are skipped, photos stay in the database. */
const RESEND_KEY = process.env.RESEND_API_KEY || "";
const MAIL_FROM = process.env.MAIL_FROM || "FabriTrade <onboarding@resend.dev>";
const APP_URL = (process.env.APP_URL || "https://fabritrade.net/app.html").replace(/\/$/, "");
const MAIL_BASE = (process.env.MAIL_BASE || "https://api.resend.com").replace(/\/$/, "");
async function sendMail(to, subject, text){
  if (!RESEND_KEY || !to) return false;
  try {
    const r = await fetch(MAIL_BASE + "/emails", { method:"POST", headers:{ Authorization:"Bearer " + RESEND_KEY, "Content-Type":"application/json" },
      body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, text: text + "\n\n— FabriTrade · fabritrade.net\nQuestions: support@fabritrade.net" }) });
    if (!r.ok) { console.error("Email failed:", r.status, (await r.text()).slice(0, 200)); return false; }
    return true;
  } catch (e) { console.error("Email failed:", e.message); return false; }
}
const CLD_NAME = process.env.CLOUDINARY_CLOUD_NAME || "", CLD_KEY = process.env.CLOUDINARY_API_KEY || "", CLD_SECRET = process.env.CLOUDINARY_API_SECRET || "";
const CLD_BASE = (process.env.CLOUDINARY_BASE || "https://api.cloudinary.com").replace(/\/$/, "");
const USE_CLD = !!(CLD_NAME && CLD_KEY && CLD_SECRET);
function isDataImage(x){ return typeof x === "string" && /^data:image\/(jpeg|png|webp);base64,/.test(x); }
async function storeImage(dataUrl, folder){
  if (!isDataImage(dataUrl)) return typeof dataUrl === "string" && /^https:\/\//.test(dataUrl) ? dataUrl : "";
  if (dataUrl.length > 1.5e6) throw new Error("Photo is too large. Please use a smaller photo.");
  if (!USE_CLD) return dataUrl; // fallback: keep it in the database (fine for a few photos)
  const ts = Math.floor(now() / 1000), fld = "fabritrade/" + (folder || "listings");
  const sig = crypto.createHash("sha1").update("folder=" + fld + "&timestamp=" + ts + CLD_SECRET).digest("hex");
  const form = new URLSearchParams({ file: dataUrl, api_key: CLD_KEY, timestamp: String(ts), folder: fld, signature: sig });
  const r = await fetch(CLD_BASE + "/v1_1/" + CLD_NAME + "/image/upload", { method:"POST", body: form });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.secure_url) throw new Error("Image upload failed" + (j.error && j.error.message ? ": " + j.error.message : ""));
  return j.secure_url;
}
/* visitor counts: no cookies; a daily-salted hash of IP + browser is kept in memory only to avoid double counting */
const seenToday = { day: "", set: new Set() };
function today(){ return new Date().toISOString().slice(0, 10); }
function countHit(req, page){
  const d = today(); if (seenToday.day !== d) { seenToday.day = d; seenToday.set = new Set(); }
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?").split(",")[0];
  const h = crypto.createHash("sha256").update(d + db.secret + ip + (req.headers["user-agent"] || "")).digest("hex").slice(0, 16);
  const st = db.stats[d] || (db.stats[d] = { views: 0, visitors: 0, pages: {} });
  st.views++; st.pages[page] = (st.pages[page] || 0) + 1;
  if (!seenToday.set.has(h)) { seenToday.set.add(h); st.visitors++; }
  const keys = Object.keys(db.stats).sort(); while (keys.length > 120) delete db.stats[keys.shift()];
}
const ipHits = new Map();
function ipAllowed(req, key, max, ms){ const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?").split(",")[0]; const k = key + ip, t = now(), arr = (ipHits.get(k) || []).filter(x => t - x < ms); if (arr.length >= max) return false; arr.push(t); ipHits.set(k, arr); return true; }
const mailNotified = new Map(); // userId -> last "new message" email time
const clean = (v, n) => String(v == null ? "" : v).replace(/[<>]/g, "").trim().slice(0, n);
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
/* simple per-user rate limit for messages */
const msgHits = new Map();
function msgAllowed(id){ const t = now(), arr = (msgHits.get(id) || []).filter(x => t - x < 60e3); if (arr.length >= 30) return false; arr.push(t); msgHits.set(id, arr); return true; }

/* ================= Real AI (Google Gemini, free tier) =================
   Set GEMINI_API_KEY on Render. Optional: GEMINI_MODEL, NEWS_HOURS (default 8).
   Without a key, everything keeps working with the built-in demo answers/news. */
const GEMINI_KEY = process.env.GEMINI_API_KEY || "";
const GEMINI_MODELS = ["gemini-flash-latest", "gemini-flash-lite-latest", "gemini-2.5-flash", "gemini-2.5-flash-lite"];
const NEWS_HOURS = +process.env.NEWS_HOURS || 8;
const GEMINI_BASE = (process.env.GEMINI_BASE || "https://generativelanguage.googleapis.com").replace(/\/$/, "");
let goodModel = null;

async function gemini(prompt, { search = false, system = "", maxTokens = 2048 } = {}){
  if (!GEMINI_KEY) throw new Error("No GEMINI_API_KEY set");
  const payload = { contents: [{ role: "user", parts: [{ text: prompt }] }], generationConfig: { temperature: 0.4, maxOutputTokens: maxTokens } };
  if (system) payload.systemInstruction = { parts: [{ text: system }] };
  if (search) payload.tools = [{ google_search: {} }];
  const found = await discoverModels();
  const tryList = [goodModel, process.env.GEMINI_MODEL, ...found, ...GEMINI_MODELS].filter(Boolean);
  const errs = [];
  for (const model of [...new Set(tryList)].slice(0, 6)) {
    try {
      const r = await fetch(GEMINI_BASE + "/v1beta/models/" + model + ":generateContent", {
        method: "POST", headers: { "Content-Type": "application/json", "x-goog-api-key": GEMINI_KEY }, body: JSON.stringify(payload) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { errs.push(model + ": " + String((j.error && j.error.message) || r.status).slice(0, 160)); if (goodModel === model) goodModel = null; continue; }
      const c = (j.candidates || [])[0] || {};
      const text = ((c.content && c.content.parts) || []).map(x => x.text || "").join("").trim();
      const sources = (((c.groundingMetadata || {}).groundingChunks) || []).map(g => g.web).filter(Boolean).map(w => ({ title: w.title || "", url: w.uri || "" }));
      goodModel = model;
      return { text, sources, model };
    } catch (e) { errs.push(model + ": " + e.message); }
  }
  throw new Error(errs.length ? errs.join(" | ") : "AI unavailable");
}
/* Ask Google which models this key can use (models get retired, so don't hard-code). */
let modelCache = null, modelCacheAt = 0;
async function discoverModels(){
  if (modelCache && now() - modelCacheAt < 12 * 3600e3) return modelCache;
  try {
    const r = await fetch(GEMINI_BASE + "/v1beta/models?pageSize=200", { headers: { "x-goog-api-key": GEMINI_KEY } });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { console.error("Gemini model list failed:", (j.error && j.error.message) || r.status); return []; }
    const ver = n => { const m = n.match(/gemini-(\d+(?:\.\d+)?)/); return m ? +m[1] : 0; };
    const bad = /image|tts|audio|live|embed|vision|robotics|computer|native|exp|learnlm|gemma/i;
    const list = (j.models || []).filter(m => (m.supportedGenerationMethods || []).includes("generateContent"))
      .map(m => String(m.name || "").replace(/^models\//, "")).filter(n => /^gemini-/.test(n) && /flash/.test(n) && !bad.test(n));
    const score = n => ver(n) * 10 - (/preview/.test(n) ? 3 : 0) - (/lite/.test(n) ? 1 : 0) - (/-\d{3,}$|latest/.test(n) ? 0.5 : 0);
    modelCache = list.sort((a, b) => score(b) - score(a)).slice(0, 5); modelCacheAt = now();
    console.log("Gemini models available:", modelCache.join(", ") || "(none)");
    return modelCache;
  } catch (e) { console.error("Gemini model list failed:", e.message); return []; }
}
function extractJSON(text){
  const s = String(text || "").replace(/```json|```/g, "");
  const a = s.indexOf("["), b = s.lastIndexOf("]");
  const o = s.indexOf("{"), e = s.lastIndexOf("}");
  for (const [x, y] of [[a, b], [o, e]]) { if (x >= 0 && y > x) { try { return JSON.parse(s.slice(x, y + 1)); } catch {} } }
  return null;
}

/* ---- AI Price Watch: real news, refreshed automatically ---- */
let newsBusy = null;
const tri = v => (v && typeof v === "object") ? { en: String(v.en || ""), zh: String(v.zh || v.en || ""), vi: String(v.vi || v.en || "") } : { en: String(v || ""), zh: String(v || ""), vi: String(v || "") };
/* Free headlines from Google News RSS (no key, no quota). */
const NEWS_QUERIES = [["cotton prices", "Cotton"], ["oil prices polyester", "Polyester"], ["textile tariffs Vietnam", "VN textiles"],
  ["container shipping freight rates", "All imports"], ["silk prices", "Silk"], ["textile industry garment exports", "All fabrics"]];
const NEWS_FEED = process.env.NEWS_FEED_BASE || "https://news.google.com/rss/search";
const unxml = s => String(s || "").replace(/<!\[CDATA\[|\]\]>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/<[^>]+>/g, "").trim();
async function fetchHeadlines(){
  const out = [], seen = new Set();
  await Promise.all(NEWS_QUERIES.map(async ([q, fabric]) => {
    try {
      const r = await fetch(NEWS_FEED + "?q=" + encodeURIComponent(q + " when:14d") + "&hl=en-US&gl=US&ceid=US:en", { headers: { "User-Agent": "Mozilla/5.0 FabriTrade" } });
      if (!r.ok) return;
      const xml = await r.text();
      (xml.match(/<item>[\s\S]*?<\/item>/g) || []).slice(0, 4).forEach(it => {
        const g = tag => { const m = it.match(new RegExp("<" + tag + "[^>]*>([\\s\\S]*?)<\\/" + tag + ">")); return m ? unxml(m[1]) : ""; };
        let title = g("title"); const source = g("source") || (title.includes(" - ") ? title.split(" - ").pop() : "");
        if (source && title.endsWith(" - " + source)) title = title.slice(0, -(source.length + 3));
        const key = title.toLowerCase().slice(0, 60); if (!title || seen.has(key)) return; seen.add(key);
        const d = new Date(g("pubDate")); out.push({ title, source, url: g("link"), date: isNaN(d) ? "" : d.toISOString().slice(0, 10), fabric, q });
      });
    } catch (e) { console.error("Headline fetch failed (" + q + "):", e.message); }
  }));
  return out.sort((a, b) => (b.date || "").localeCompare(a.date || ""));
}
/* Simple backup if the AI is unavailable: guess direction from the headline words. */
function basicItem(h){
  const t = h.title.toLowerCase();
  const up = /(rise|rises|rising|surge|jump|soar|climb|higher|hike|spike|tariff|shortage|drought|disrupt|delay|strike|record high|increase)/.test(t);
  const down = /(fall|falls|drop|slump|plunge|lower|decline|cut|ease|eases|cheaper|surplus|glut|slide|weak)/.test(t);
  const dir = down && !up ? "down" : "up";
  const note = { en: "Headline only (AI summary unavailable right now). Tap the source to read more.", zh: "仅标题（AI 摘要暂不可用）。点击来源查看详情。", vi: "Chỉ có tiêu đề (tóm tắt AI tạm thời không có). Bấm nguồn để đọc thêm." };
  return { dir, pct: 0, fabric: tri(h.fabric), title: tri(h.title), note, source: h.source, date: h.date, url: h.url };
}
async function refreshNews(reason){
  if (newsBusy) return newsBusy;
  newsBusy = (async () => {
    try {
      const heads = (await fetchHeadlines()).slice(0, 18);
      if (!heads.length) throw new Error("Couldn't load news headlines");
      let items = null, model = "", aiErr = "";
      if (GEMINI_KEY) {
        try {
          const list = heads.map((h, i) => `${i}. [${h.fabric}] ${h.title} (${h.source}, ${h.date})`).join("\n");
          const prompt = `Today is ${new Date().toISOString().slice(0, 10)}. Below are recent news headlines. Pick the 6 that matter most for textile and fabric prices (cotton, polyester/oil, silk, linen, freight, tariffs and trade especially Vietnam/China/US/EU). For each give a short buyer-friendly price outlook.
Headlines:
${list}
Reply with ONLY a JSON array, no other text. Each item:
{"i":<headline number>,"dir":"up" or "down","pct":<estimated % price impact, integer 1-15>,"fabric":{"en":"...","zh":"...","vi":"..."},"title":{"en":"short headline","zh":"...","vi":"..."},"note":{"en":"AI: one or two sentences on what it means for fabric buyers/sellers","zh":"...","vi":"..."}}
zh = Simplified Chinese, vi = Vietnamese. Base everything only on the headlines given.`;
          const r = await gemini(prompt, { maxTokens: 4096 });
          const arr = extractJSON(r.text);
          if (!Array.isArray(arr) || !arr.length) throw new Error("AI returned no usable news");
          items = arr.slice(0, 8).map(n => { const h = heads[+n.i] || {}; return {
            dir: n.dir === "down" ? "down" : "up", pct: Math.max(1, Math.min(30, Math.round(+n.pct || 3))),
            fabric: tri(n.fabric || h.fabric), title: tri(n.title || h.title), note: tri(n.note),
            source: String(h.source || "").slice(0, 80), date: h.date || "", url: h.url || "" }; }).filter(n => n.title.en);
          model = r.model;
        } catch (e) { aiErr = e.message; console.error("AI summary failed, showing headlines only:", e.message.slice(0, 300)); }
      }
      if (!items || !items.length) items = heads.slice(0, 6).map(basicItem);
      db.news = { items, updated: now(), model, basic: !model, error: aiErr ? "AI summary unavailable: " + aiErr.slice(0, 300) : "" };
      logAdmin("Price Watch updated (" + items.length + " stories, " + (model ? "AI summary" : "headlines only") + (reason ? ", " + reason : "") + ")");
      saveDB(); return db.news;
    } catch (e) {
      console.error("News refresh failed:", e.message);
      db.news = Object.assign({ items: [] }, db.news || {}, { error: e.message, tried: now() }); saveDB();
      return null;
    } finally { newsBusy = null; }
  })();
  return newsBusy;
}
function newsStale(){ const n = db.news || {}; const last = Math.max(n.updated || 0, n.tried || 0); const hrs = (n.basic && GEMINI_KEY) ? Math.min(2, NEWS_HOURS) : NEWS_HOURS; return now() - last > hrs * 3600e3; }

/* ---- AI assistant (rate-limited so the free quota lasts) ---- */
const aiHits = new Map();
function aiAllowed(key){ const t = now(), arr = (aiHits.get(key) || []).filter(x => t - x < 3600e3); if (arr.length >= 20) return false; arr.push(t); aiHits.set(key, arr); return true; }
const ASSIST_SYSTEM = `You are the FabriTrade assistant. FabriTrade (fabritrade.net) is an online marketplace for buying, selling and trading fabric between Vietnam and the world, for both businesses and small buyers. Facts: anyone with an account can buy and sell; sellers list fabric with photos, price per metre, MOQ (minimum order) and bulk price breaks (5x MOQ = 8% off, 20x MOQ = 15% off); buyers can order samples; payment is held in escrow until the buyer confirms delivery; the platform takes a 3.5% commission from the seller on each sale; buyers can post an RFQ (request for quote) and sellers send offers; sellers can boost listings to Featured; the Price Watch page shows news that affects fabric prices; never pay or chat outside the platform (that is how scams happen). Help with fabric types, GSM, sourcing, pricing, shipping/Incoterms, customs and how to use the site. Be brief (under 120 words), friendly and practical. Reply in the user's language. If unsure, say so. Never invent specific sellers, prices or orders.`;

/* ---- AI owner report for the Manager ---- */
async function ownerReport(){
  const done = db.orders.filter(o => o.status !== "refunded"); const week = now() - 7 * 864e5;
  const facts = { users: db.users.length, newUsers7d: db.users.filter(u => (u.createdAt || 0) > week).length, listings: db.listings.length,
    orders: done.length, orders7d: done.filter(o => (o.createdAt || 0) > week).length, gmv: +done.reduce((s, o) => s + o.total, 0).toFixed(2),
    commissionEarned: +(db.revenue.commission || 0).toFixed(2), inEscrow: db.orders.filter(o => o.status === "in_escrow").length,
    openFlagReasons: db.flags.filter(f => !f.done).map(f => f.reason).slice(0, 10), // reasons only — no names or message text go to the AI
    unverifiedSellers: db.users.filter(x => x.role !== "buyer" && !x.verified).length, openRfqs: db.rfqs.filter(r => !r.closed).length,
    hiddenListings: db.listings.filter(l => l.hidden).length, newsHeadlines: ((db.news || {}).items || []).map(n => n.title.en) };
  const r = await gemini("Here is today's data for my fabric marketplace FabriTrade (I'm the owner):\n" + JSON.stringify(facts) +
    "\nWrite a short owner briefing in simple English: 1) how the business is doing, 2) up to 5 things I should do today (most important first: scam flags, unverified sellers, stuck orders), 3) one growth idea based on the news. Use short bullet points, under 180 words. No markdown headings.", { maxTokens: 1024 });
  db.aiReport = { text: r.text, at: now() }; saveDB(); return db.aiReport;
}

/* ================= API ================= */
async function api(req, res, url){
  const p = url.pathname, m = req.method;
  if (m === "OPTIONS") { cors(res); res.writeHead(204); return res.end(); }
  const S = db.settings;
  // Suspended accounts are blocked everywhere, immediately — even on devices that are already logged in.
  { const t = bearer(req); if (t) { const r = readToken(t); if (r && r.user.suspended && p !== "/api/health") return send(res, 403, { error:"This account is suspended. Contact support.", suspended:true }); } }

  /* ---- public ---- */
  if (p === "/api/health") return send(res, 200, { ok:true, mode:"live", prelaunch:!!S.prelaunch, launchText:S.launchText||"", maintenance:S.maintenance, announcement:S.announcement, commission:S.commission, boostFee:S.boostFee, sampleFee:S.sampleFee });
  if (p === "/api/stats") {
    const done = db.orders.filter(o => o.status !== "refunded");
    return send(res, 200, { users: db.users.length, listings: db.listings.length, orders: done.length, gmv: +done.reduce((s,o)=>s+o.total,0).toFixed(2), countries: 50 });
  }

  /* ---- visitor counting (no cookies) ---- */
  if (p === "/api/hit" && m === "POST") { const b = await body(req); countHit(req, clean(b.page, 20) || "page"); saveDB(); return send(res, 200, { ok:true }); }

  /* ---- free swatch requests (no account needed) ---- */
  if (p === "/api/swatch" && m === "POST") {
    if (!ipAllowed(req, "sw:", 8, 3600e3)) return send(res, 429, { error:"Too many requests from this network. Please try again later." });
    const b = await body(req);
    const email = clean(b.email, 160).toLowerCase();
    if (!validEmail(email)) return send(res, 400, { error:"Please enter a valid email." });
    if (b.consent !== true) return send(res, 400, { error:"Please tick the box so we can contact you about this swatch." });
    const l = db.listings.find(x => x.id === +b.listingId);
    const sw = { id: nextId("swatch"), listingId: l ? l.id : null, fabric: l ? l.title : clean(b.fabric, 120), type: l ? l.type : clean(b.type, 40),
      email, name: clean(b.name, 80), company: clean(b.company, 80), country: clean(b.country, 60), qty: clean(b.qty, 40), note: clean(b.note, 500),
      lang: ["en","zh","vi"].includes(b.lang) ? b.lang : "en", status: "new", createdAt: now() };
    db.swatches.unshift(sw); logAdmin("Swatch request: " + (sw.fabric || "fabric") + (sw.country ? " · " + sw.country : "")); saveDB();
    const firstName = sw.name ? " " + sw.name.split(" ")[0] : "";
    sendMail(email, "We received your swatch request", "Hi" + firstName + ",\n\nThanks for requesting a swatch of " + (sw.fabric || "this fabric") + ". FabriTrade will reply within 2 business days with the next steps.\n\nYou asked for this on fabritrade.net. If it wasn't you, just ignore this email.");
    if (OWNER_EMAIL) sendMail(OWNER_EMAIL, "New swatch request: " + (sw.fabric || "fabric"), "From: " + email + (sw.country ? " (" + sw.country + ")" : "") + "\nQuantity later: " + (sw.qty || "-") + "\nNote: " + (sw.note || "-") + "\n\nOpen the Manager to follow up.");
    return send(res, 200, { ok:true });
  }

  /* ---- what buyers are asking for (anonymous, for sellers) ---- */
  if (p === "/api/demand" && m === "GET") {
    const since = now() - 90 * 864e5;
    const items = [
      ...db.swatches.filter(x => x.createdAt > since).map(x => ({ kind:"swatch", what: x.fabric || x.type || "Fabric", qty: x.qty || "", country: x.country || "", at: x.createdAt })),
      ...db.rfqs.filter(r => !r.closed && (r.createdAt || 0) > since && r.byId).map(r => ({ kind:"rfq", what: r.title, qty: r.qty ? r.qty + " m" : "", country: "", at: r.createdAt || 0 }))
    ].sort((a, b) => b.at - a.at).slice(0, 12);
    const d30 = now() - 30 * 864e5;
    return send(res, 200, { items, counts: { swatches30d: db.swatches.filter(x => x.createdAt > d30).length, rfqs30d: db.rfqs.filter(r => (r.createdAt || 0) > d30).length } });
  }

  /* ---- "we list it for you": seller submissions (no account needed) ---- */
  if (p === "/api/submit-listing" && m === "POST") {
    if (!ipAllowed(req, "sub:", 5, 3600e3)) return send(res, 429, { error:"Too many submissions from this network. Please try again later." });
    const b = await body(req);
    if (b.consent !== true) return send(res, 400, { error:"Please tick the box to agree." });
    const contact = clean(b.contact, 80);
    if (!clean(b.shop, 80) || !contact) return send(res, 400, { error:"Please add your shop name and a Zalo or phone number." });
    const photos = [];
    try { for (const ph of (Array.isArray(b.photos) ? b.photos.slice(0, 3) : [])) { const u = await storeImage(ph, "submissions"); if (u) photos.push(u); } }
    catch (e) { return send(res, 400, { error: e.message }); }
    const sub = { id: nextId("submission"), shop: clean(b.shop, 80), contact, email: validEmail(clean(b.email,160)) ? clean(b.email,160).toLowerCase() : "", market: clean(b.market, 80),
      type: clean(b.type, 40) || "Cotton", title: clean(b.title, 120), price: clean(b.price, 40), moq: clean(b.moq, 20), width: clean(b.width, 20), gsm: clean(b.gsm, 20),
      note: clean(b.note, 500), photos, status: "new", consentAt: now(), createdAt: now() };
    db.submissions.unshift(sub); logAdmin("Seller submission: " + sub.shop); saveDB();
    if (OWNER_EMAIL) sendMail(OWNER_EMAIL, "New seller submission: " + sub.shop, "Shop: " + sub.shop + "\nContact: " + sub.contact + "\nMarket: " + (sub.market || "-") + "\nFabric: " + (sub.title || sub.type) + " · " + (sub.price || "-") + "\n\nOpen the Manager to review and publish.");
    return send(res, 200, { ok:true });
  }

  /* ---- image upload for logged-in sellers ---- */
  if (p === "/api/upload" && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    if (!ipAllowed(req, "up:", 40, 3600e3)) return send(res, 429, { error:"Too many uploads. Please wait a bit." });
    const b = await body(req);
    try { const url = await storeImage(b.dataUrl, "listings"); if (!url) return send(res, 400, { error:"That doesn't look like a photo." }); return send(res, 200, { url, hosted: /^https:/.test(url) }); }
    catch (e) { return send(res, 400, { error: e.message }); }
  }

  /* ---- forgot password ---- */
  if (p === "/api/password/forgot" && m === "POST") {
    if (!ipAllowed(req, "pw:", 5, 3600e3)) return send(res, 429, { error:"Too many tries. Please wait a bit." });
    const b = await body(req); const email = clean(b.email, 160).toLowerCase();
    const u = db.users.find(x => x.email === email);
    if (u && !u.seed) {
      const tok = crypto.randomBytes(24).toString("hex");
      u.resetHash = crypto.createHash("sha256").update(tok).digest("hex"); u.resetExp = now() + 3600e3; saveDB();
      sendMail(u.email, "Reset your FabriTrade password", "Someone (hopefully you) asked to reset your FabriTrade password.\n\nOpen this link within 1 hour to choose a new one:\n" + APP_URL + "#reset=" + tok + "\n\nIf you didn't ask for this, you can ignore this email; your password stays the same.");
    }
    return send(res, 200, { ok:true, emailEnabled: !!RESEND_KEY }); // same answer either way, so nobody can test which emails have accounts
  }
  if (p === "/api/password/reset" && m === "POST") {
    const b = await body(req); const h = crypto.createHash("sha256").update(String(b.token || "")).digest("hex");
    const u = db.users.find(x => x.resetHash && x.resetHash === h && x.resetExp > now());
    if (!u) return send(res, 400, { error:"This reset link is invalid or has expired. Please ask for a new one." });
    if (String(b.newPassword || "").length < 6) return send(res, 400, { error:"New password must be at least 6 characters." });
    const { salt, hash } = hashPassword(b.newPassword); u.salt = salt; u.hash = hash; u.tokenVer = (u.tokenVer || 0) + 1; delete u.resetHash; delete u.resetExp; saveDB();
    return send(res, 200, { ok:true, token: makeToken(u.id), user: pub(u) });
  }

  /* ---- Waitlist (launch updates) ---- */
  if (p === "/api/waitlist" && m === "POST") {
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?").split(",")[0];
    if (!wlAllowed(ip)) return send(res, 429, { error:"Too many sign-ups from this network. Please try again later." });
    const b = await body(req);
    const email = String(b.email || "").toLowerCase().trim().slice(0, 160);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return send(res, 400, { error:"Please enter a valid email." });
    if (b.consent !== true) return send(res, 400, { error:"Please tick the box to agree to receive launch updates." });
    const entry = { email, role: ["buyer","seller","both"].includes(b.role) ? b.role : "buyer", country: String(b.country || "").slice(0, 60), fabrics: String(b.fabrics || "").slice(0, 200), lang: ["en","zh","vi"].includes(b.lang) ? b.lang : "en", source: String(b.source || "landing").slice(0, 30) };
    const old = db.waitlist.find(w => w.email === email);
    if (old) { Object.assign(old, entry, { updatedAt: now() }); saveDB(); return send(res, 200, { ok:true, already:true }); }
    db.waitlist.unshift({ id: nextId("wait"), ...entry, consentAt: now(), consentText: String(b.consentText || "waitlist-v1").slice(0, 20), createdAt: now() }); saveDB();
    return send(res, 200, { ok:true });
  }
  if (p === "/api/waitlist/unsubscribe" && m === "GET") {
    const email = String(url.searchParams.get("e") || "").toLowerCase().trim(), tok = String(url.searchParams.get("t") || "");
    const ok = email && tok === unsubToken(email);
    if (ok) { const before = db.waitlist.length; db.waitlist = db.waitlist.filter(w => w.email !== email); if (db.waitlist.length !== before) { logAdmin("Waitlist unsubscribe: " + email); saveDB(); } }
    cors(res); res.writeHead(ok ? 200 : 400, { "Content-Type":"text/html; charset=utf-8" });
    return res.end(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>FabriTrade</title><div style="font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:480px;margin:80px auto;padding:0 20px;color:#0f172a"><h2 style="color:#1f4e79">FabriTrade</h2><p>${ok ? "You have been removed from the FabriTrade waitlist. You won't receive any more launch emails." : "This unsubscribe link is not valid. Email support@fabritrade.net and we'll remove you."}</p><p><a href="https://fabritrade.net" style="color:#1f4e79">fabritrade.net</a></p></div>`);
  }

  /* ---- AI: Price Watch news + assistant ---- */
  if (p === "/api/news" && m === "GET") {
    const n = db.news || {};
    if (newsStale()) {
      const job = refreshNews("auto");
      if (!(n.items && n.items.length)) await Promise.race([job, new Promise(r => setTimeout(r, 25000))]); // first time: wait for it
    }
    const cur = db.news || {};
    return send(res, 200, { ai: !!GEMINI_KEY, items: cur.items || [], updated: cur.updated || 0, sources: cur.sources || [] });
  }
  if (p === "/api/ai/chat" && m === "POST") {
    if (!GEMINI_KEY) return send(res, 503, { error: "AI not configured", fallback: true });
    const b = await body(req); const msg = String(b.message || "").slice(0, 1000).trim();
    if (!msg) return send(res, 400, { error: "Empty message." });
    const who = auth(req); const key = who ? "u" + who.id : (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?").split(",")[0];
    if (!aiAllowed(key)) return send(res, 429, { error: "Too many questions — please try again in a bit.", fallback: true });
    const hist = Array.isArray(b.history) ? b.history.slice(-6).map(h => (h.bot ? "Assistant: " : "User: ") + String(h.t || "").slice(0, 400)).join("\n") : "";
    const lang = { zh: "Simplified Chinese", vi: "Vietnamese" }[b.lang] || "the user's language";
    try {
      const r = await gemini((hist ? "Conversation so far:\n" + hist + "\n\n" : "") + "User: " + msg + "\n(Reply in " + lang + ".)", { system: ASSIST_SYSTEM, maxTokens: 600 });
      return send(res, 200, { reply: r.text || "Sorry, I couldn't answer that." });
    } catch (e) { console.error("AI chat failed:", e.message); return send(res, 502, { error: "AI busy", fallback: true }); }
  }

  /* ---- auth ---- */
  if (p === "/api/register" && m === "POST") {
    const b = await body(req);
    if (!b.email || !b.password || !b.name) return send(res, 400, { error:"Name, email and password are required." });
    if (String(b.password).length < 6) return send(res, 400, { error:"Password must be at least 6 characters." });
    const email = String(b.email).toLowerCase().trim();
    if (db.users.some(u => u.email === email)) return send(res, 409, { error:"An account with that email already exists." });
    if (b.agreeTerms !== true) return send(res, 400, { error:"Please agree to the Terms of Service and Privacy Policy to create an account." });
    const { salt, hash } = hashPassword(b.password);
    // The first REAL account (not a demo seed) becomes the platform owner.
    const isFirst = OWNER_EMAIL
      ? (email === OWNER_EMAIL && !db.users.some(u => u.role === "owner"))
      : (!db.users.some(u => u.role === "owner") && db.users.filter(u => !u.seed).length === 0);
    const user = { id: nextId("user"), name: String(b.name).slice(0,80), email, salt, hash,
      role: isFirst ? "owner" : (b.role === "seller" ? "seller" : "buyer"), verified: isFirst, suspended:false, country: b.country||"", createdAt: now(),
      termsAcceptedAt: now(), termsVersion: String(b.termsVersion || "1.0").slice(0, 10), ageConfirmed: b.ageConfirmed === true }; // record of consent (Terms + Privacy Policy)
    db.users.push(user); if (isFirst) logAdmin("Owner account created: " + email); saveDB();
    return send(res, 200, { token: makeToken(user.id), user: pub(user), owner: isFirst });
  }
  if (p === "/api/login" && m === "POST") {
    const b = await body(req);
    const user = db.users.find(u => u.email === String(b.email||"").toLowerCase().trim());
    if (!user || !checkPassword(b.password||"", user.salt, user.hash)) return send(res, 401, { error:"Wrong email or password." });
    if (user.suspended) return send(res, 403, { error:"This account is suspended. Contact support." });
    return send(res, 200, { token: makeToken(user.id), user: pub(user) });
  }
  if (p === "/api/password" && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const b = await body(req);
    if (!checkPassword(b.oldPassword||"", u.salt, u.hash)) return send(res, 401, { error:"Your current password is wrong." });
    if (String(b.newPassword||"").length < 6) return send(res, 400, { error:"New password must be at least 6 characters." });
    const { salt, hash } = hashPassword(b.newPassword); u.salt = salt; u.hash = hash; u.tokenVer = (u.tokenVer || 0) + 1; // logs out every other device
    saveDB(); return send(res, 200, { ok:true, token: makeToken(u.id) });
  }
  if (p === "/api/me/delete" && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const b = await body(req);
    if (!checkPassword(b.password||"", u.salt, u.hash)) return send(res, 401, { error:"That password is not correct." });
    if (u.role === "owner") return send(res, 400, { error:"The owner account can't be deleted here." });
    const open = db.orders.some(o => (o.buyerId === u.id || o.sellerId === u.id) && ["in_escrow","shipped"].includes(o.status));
    if (open) return send(res, 409, { error:"Please finish your open orders first, then delete your account." });
    // remove the account, its listings and messages; keep order records (anonymised) for legal and tax reasons
    db.listings = db.listings.filter(l => l.ownerId !== u.id);
    db.messages = db.messages.filter(x => x.fromId !== u.id && x.toId !== u.id);
    db.flags.forEach(f => { if (f.fromId === u.id) { f.fromName = "Deleted user"; f.text = "[deleted]"; } });
    db.orders.forEach(o => { if (o.buyerId === u.id) o.buyerName = "Deleted user"; if (o.sellerId === u.id) o.sellerName = "Deleted user"; });
    db.rfqs = db.rfqs.filter(r => r.byId !== u.id);
    db.rfqs.forEach(r => { r.offers = (r.offers || []).filter(o => o.sellerId !== u.id); });
    db.waitlist = (db.waitlist || []).filter(w => w.email !== u.email);
    db.users = db.users.filter(x => x !== u);
    logAdmin("Account deleted by user (id " + u.id + ")"); saveDB();
    return send(res, 200, { ok:true });
  }
  if (p === "/api/logout-all" && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    u.tokenVer = (u.tokenVer || 0) + 1; saveDB(); return send(res, 200, { ok:true });
  }
  if (p === "/api/me") { const u = auth(req); return u ? send(res, 200, { user: pub(u) }) : send(res, 401, { error:"Not logged in." }); }

  /* ---- listings ---- */
  if (p === "/api/listings" && m === "GET") return send(res, 200, { listings: db.listings.filter(l=>!l.hidden).map(listingOut) });
  if (p.match(/^\/api\/listings\/\d+$/) && m === "GET") { const l = db.listings.find(x => x.id === +p.split("/")[3]); return l ? send(res, 200, { listing: listingOut(l) }) : send(res, 404, { error:"Not found." }); }
  if (p === "/api/listings" && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    if (S.requireVerify && !u.verified && u.role !== "owner") return send(res, 403, { error:"Your account must be verified before listing. The owner will review it soon." });
    const b = await body(req);
    if (isDataImage(b.img)) { try { b.img = await storeImage(b.img, "listings"); } catch (e) { return send(res, 400, { error: e.message }); } }
    const l = { id: nextId("listing"), ownerId: u.id, title: String(b.title||"Untitled fabric").slice(0,120), type: b.type||"Cotton", comp: b.comp||"", gsm:+b.gsm||0, width:+b.width||0,
      price:+b.price||0, moq: Math.max(1,+b.moq||1), origin: b.origin||"", cert: b.cert||"", color: b.color||"#cdbfa6", img: b.img||"", inco: b.inco||"FOB", stock: b.stock||"in stock", lead:+b.lead||7, rating:5.0, featured:false, createdAt: now() };
    if (S.prelaunch && !u.founding) { u.founding = true; logAdmin("Founding seller: " + u.name); }
    db.listings.unshift(l); saveDB(); return send(res, 200, { listing: listingOut(l) });
  }
  if (p.match(/^\/api\/listings\/\d+$/) && (m === "PUT" || m === "DELETE")) {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const l = db.listings.find(x => x.id === +p.split("/")[3]); if (!l) return send(res, 404, { error:"Not found." });
    if (l.ownerId !== u.id && u.role !== "owner") return send(res, 403, { error:"Not your listing." });
    if (m === "DELETE") { db.listings = db.listings.filter(x => x !== l); saveDB(); return send(res, 200, { ok:true }); }
    const b = await body(req);
    ["title","type","comp","origin","cert","color","img","inco","stock"].forEach(k => { if (b[k] !== undefined) l[k] = b[k]; });
    ["gsm","width","price","moq","lead"].forEach(k => { if (b[k] !== undefined) l[k] = +b[k]; });
    saveDB(); return send(res, 200, { listing: listingOut(l) });
  }
  if (p.match(/^\/api\/listings\/\d+\/boost$/) && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const l = db.listings.find(x => x.id === +p.split("/")[3]); if (!l) return send(res, 404, { error:"Not found." });
    if (l.ownerId !== u.id) return send(res, 403, { error:"Not your listing." });
    if (S.prelaunch) return send(res, 403, { error:"Paid boosts open at our full launch" + (S.launchText ? " in " + S.launchText : "") + ".", prelaunch:true });
    l.featured = true; l.boostedAt = now(); db.revenue.boosts += +S.boostFee; saveDB();
    return send(res, 200, { listing: listingOut(l), fee: S.boostFee }); // real Stripe charge for the boost fee goes here
  }
  if (p === "/api/my/listings" && m === "GET") { const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." }); return send(res, 200, { listings: db.listings.filter(x => x.ownerId === u.id).map(listingOut) }); }

  /* ---- orders (escrow + commission) ---- */
  if (p === "/api/orders" && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in to buy." });
    if (S.maintenance && u.role !== "owner") return send(res, 503, { error:"The marketplace is in maintenance mode. Please try again soon." });
    if (S.prelaunch) return send(res, 403, { error:"Ordering and payments open at our full launch" + (S.launchText ? " in " + S.launchText : "") + ". For now you can browse, message sellers and post requests.", prelaunch:true });
    const b = await body(req);
    const l = db.listings.find(x => x.id === +b.listingId); if (!l) return send(res, 404, { error:"Listing not found." });
    if (l.ownerId === u.id) return send(res, 400, { error:"You can't buy your own listing." });
    const seller = db.users.find(x => x.id === l.ownerId);
    let qty, total, sample = !!b.sample;
    if (sample) { qty = "swatch"; total = +S.sampleFee; }
    else { qty = Math.max(l.moq, +b.qty || l.moq); const unit = unitPrice(l, qty); total = +(qty * unit).toFixed(2); }
    const commission = +(total * COMM()).toFixed(2);
    const order = { id: nextId("order"), buyerId: u.id, buyerName: u.name, sellerId: l.ownerId, sellerName: seller ? seller.name : "Seller", listingId: l.id, title: l.title, qty, price: l.price, total, commission,
      sellerPayout: +(total - commission).toFixed(2), sample, status: "in_escrow", step: 1, createdAt: now() };
    // --- Real payment: create a Stripe PaymentIntent here and only continue after it succeeds ---
    db.orders.unshift(order); db.revenue.commission += commission; saveDB();
    return send(res, 200, { order });
  }
  if (p === "/api/my/orders" && m === "GET") { const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." }); return send(res, 200, { orders: db.orders.filter(o => o.buyerId === u.id) }); }
  if (p === "/api/seller/orders" && m === "GET") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const orders = db.orders.filter(o => o.sellerId === u.id);
    return send(res, 200, { orders, revenue: +orders.reduce((s,o)=>s+o.sellerPayout,0).toFixed(2), commission: +orders.reduce((s,o)=>s+o.commission,0).toFixed(2) });
  }
  if (p.match(/^\/api\/orders\/\d+\/(ship|confirm)$/) && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const o = db.orders.find(x => x.id === +p.split("/")[3]); if (!o) return send(res, 404, { error:"Order not found." });
    const action = p.split("/")[4];
    if (action === "ship") { if (o.sellerId !== u.id) return send(res, 403, { error:"Only the seller can mark shipped." }); o.status = "shipped"; o.step = 2; }
    else { if (o.buyerId !== u.id) return send(res, 403, { error:"Only the buyer can confirm delivery." }); o.status = "released"; o.step = 3; } // escrow release → Stripe transfer to seller here
    saveDB(); return send(res, 200, { order: o });
  }

  /* ---- RFQs ---- */
  if (p === "/api/rfqs" && m === "GET") return send(res, 200, { rfqs: db.rfqs.filter(r => !r.closed) });
  if (p === "/api/rfqs" && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const b = await body(req); if (!b.title) return send(res, 400, { error:"Tell sellers what you need." });
    const r = { id: nextId("rfq"), byId: u.id, by: u.name, title: String(b.title).slice(0,120), type: b.type||"Cotton", qty:+b.qty||100, budget:+b.budget||0, notes: String(b.notes||"").slice(0,300), offers:[], closed:false, createdAt: now() };
    db.rfqs.unshift(r); saveDB(); return send(res, 200, { rfq: r });
  }
  if (p.match(/^\/api\/rfqs\/\d+\/offers$/) && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const r = db.rfqs.find(x => x.id === +p.split("/")[3]); if (!r || r.closed) return send(res, 404, { error:"Request not found." });
    const b = await body(req);
    r.offers.push({ sellerId: u.id, seller: u.name, price: +b.price || r.budget, note: String(b.note||"").slice(0,200), at: now() }); saveDB();
    return send(res, 200, { rfq: r });
  }

  /* ---- messages (with AI moderation) ---- */
  if (p === "/api/messages" && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    if (!msgAllowed(u.id)) return send(res, 429, { error:"You're sending messages too fast. Please wait a minute." });
    const b = await body(req); if (!b.toId || !b.text) return send(res, 400, { error:"Recipient and text required." });
    if (+b.toId === u.id) return send(res, 400, { error:"You can't message yourself." });
    const to = db.users.find(x => x.id === +b.toId); if (!to) return send(res, 404, { error:"Recipient not found." });
    const text = String(b.text).slice(0, 2000);
    const reason = S.autoFlag ? riskReason(text) : null;
    const msg = { id: nextId("message"), fromId: u.id, toId: to.id, listingId: +b.listingId || null, text, flagged: !!reason, createdAt: now() };
    db.messages.push(msg);
    if (RESEND_KEY && to.email && !to.seed && now() - (mailNotified.get(to.id) || 0) > 3600e3) { mailNotified.set(to.id, now()); sendMail(to.email, "New message on FabriTrade from " + u.name, "You have a new message from " + u.name + " on FabriTrade.\n\nRead and reply here: " + APP_URL + "\n\nFor your safety, keep chats and payments on FabriTrade."); }
    if (reason) db.flags.unshift({ id: nextId("flag"), messageId: msg.id, fromId: u.id, fromName: u.name, toName: to.name, text, reason, at: now(), done:false });
    saveDB(); return send(res, 200, { message: { ...msg, mine:true } });
  }
  if (p === "/api/messages" && m === "GET") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const w = +url.searchParams.get("withUserId");
    const msgs = db.messages.filter(x => (x.fromId===u.id && x.toId===w) || (x.fromId===w && x.toId===u.id)).sort((a,b)=>a.createdAt-b.createdAt).map(x => ({ ...x, mine: x.fromId===u.id }));
    const other = db.users.find(x => x.id === w);
    return send(res, 200, { messages: msgs, with: other ? publicUser(other) : null });
  }
  if (p === "/api/messages/threads" && m === "GET") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const map = {};
    db.messages.filter(x => x.fromId===u.id || x.toId===u.id).forEach(x => { const o = x.fromId===u.id ? x.toId : x.fromId; if (!map[o] || x.createdAt > map[o].createdAt) map[o] = { lastText: x.text, createdAt: x.createdAt }; });
    const threads = Object.keys(map).map(id => { const o = db.users.find(x => x.id === +id); return { userId:+id, name: o ? o.name : "User", ...map[id] }; }).sort((a,b)=>b.createdAt-a.createdAt);
    return send(res, 200, { threads });
  }
  if (p === "/api/users/lookup" && m === "GET") { // find a user id by listing (to start a chat)
    const id = +url.searchParams.get("listingId"); const l = db.listings.find(x => x.id === id);
    return l ? send(res, 200, { user: publicUser(db.users.find(x => x.id === l.ownerId)) }) : send(res, 404, { error:"Not found." });
  }

  /* ---- OWNER / ADMIN API (used by the Manager site) ---- */
  if (p.startsWith("/api/admin/")) {
    const tk = readToken(bearer(req));
    if (!tk) return send(res, 401, { error:"Session expired. Please log in again.", expired:true });
    const u = tk.user; if (u.role !== "owner" || u.suspended) return send(res, 403, { error:"Owner access only." });
    if (tk.age > ADMIN_HOURS * 3600e3) return send(res, 401, { error:"Manager session expired (12 hours). Please log in again.", expired:true });
    const sub = p.replace("/api/admin/", "");
    if (sub === "overview" && m === "GET") {
      const done = db.orders.filter(o => o.status !== "refunded");
      return send(res, 200, { settings: S, revenue: { commission:+db.revenue.commission.toFixed(2), boosts:+db.revenue.boosts.toFixed(2) },
        stats: { users: db.users.length, sellers: db.users.filter(x=>x.role!=="buyer").length, listings: db.listings.length, featured: db.listings.filter(x=>x.featured).length,
          orders: done.length, gmv:+done.reduce((s,o)=>s+o.total,0).toFixed(2), escrow:+db.orders.filter(o=>o.status==="in_escrow").reduce((s,o)=>s+o.total,0).toFixed(2),
          shipped: db.orders.filter(o=>o.status==="shipped").length, openRfqs: db.rfqs.filter(r=>!r.closed).length, openFlags: db.flags.filter(f=>!f.done).length, waitlist: db.waitlist.length, unverified: db.users.filter(x=>x.role!=="buyer"&&!x.verified).length },
        log: db.log.slice(0, 50) });
    }
    if (sub === "users" && m === "GET") return send(res, 200, { users: db.users.map(pub).map(x => ({ ...x, risk: db.flags.some(f => !f.done && f.fromId === x.id) })) });
    if (sub.match(/^users\/\d+$/)) {
      const t = db.users.find(x => x.id === +sub.split("/")[1]); if (!t) return send(res, 404, { error:"User not found." });
      if (m === "DELETE") { if (t.role === "owner") return send(res, 400, { error:"Can't delete the owner." }); db.users = db.users.filter(x => x !== t); logAdmin("Deleted user " + t.email); saveDB(); return send(res, 200, { ok:true }); }
      const b = await body(req); if (t.role === "owner" && b.suspended) return send(res, 400, { error:"Can't suspend the owner." }); ["verified","suspended"].forEach(k => { if (b[k] !== undefined) t[k] = !!b[k]; }); if (b.suspended) t.tokenVer = (t.tokenVer || 0) + 1; if (b.role && ["buyer","seller"].includes(b.role) && t.role !== "owner") t.role = b.role;
      logAdmin("Updated user " + t.email + " " + JSON.stringify(b)); saveDB(); return send(res, 200, { user: pub(t) });
    }
    if (sub === "listings" && m === "GET") return send(res, 200, { listings: db.listings.map(listingOut) });
    if (sub.match(/^listings\/\d+$/)) {
      const l = db.listings.find(x => x.id === +sub.split("/")[1]); if (!l) return send(res, 404, { error:"Not found." });
      if (m === "DELETE") { db.listings = db.listings.filter(x => x !== l); logAdmin("Removed listing: " + l.title); saveDB(); return send(res, 200, { ok:true }); }
      const b = await body(req); if (b.featured !== undefined) l.featured = !!b.featured; if (b.price !== undefined) l.price = +b.price; if (b.hidden !== undefined) l.hidden = !!b.hidden;
      logAdmin("Updated listing " + l.title + " " + JSON.stringify(b)); saveDB(); return send(res, 200, { listing: listingOut(l) });
    }
    if (sub === "orders" && m === "GET") return send(res, 200, { orders: db.orders });
    if (sub.match(/^orders\/\d+$/) && m === "PUT") {
      const o = db.orders.find(x => x.id === +sub.split("/")[1]); if (!o) return send(res, 404, { error:"Not found." });
      const b = await body(req); if (["in_escrow","shipped","released","refunded"].includes(b.status)) { o.status = b.status; o.step = { in_escrow:1, shipped:2, released:3, refunded:0 }[b.status]; }
      logAdmin("Order #" + o.id + " → " + o.status); saveDB(); return send(res, 200, { order: o }); // release/refund → Stripe transfer/refund here
    }
    if (sub === "rfqs" && m === "GET") return send(res, 200, { rfqs: db.rfqs });
    if (sub.match(/^rfqs\/\d+$/)) {
      const r = db.rfqs.find(x => x.id === +sub.split("/")[1]); if (!r) return send(res, 404, { error:"Not found." });
      if (m === "DELETE") { db.rfqs = db.rfqs.filter(x => x !== r); logAdmin("Removed RFQ " + r.title); saveDB(); return send(res, 200, { ok:true }); }
      const b = await body(req); if (b.closed !== undefined) r.closed = !!b.closed; logAdmin((r.closed?"Closed":"Reopened") + " RFQ " + r.title); saveDB(); return send(res, 200, { rfq: r });
    }
    if (sub === "flags" && m === "GET") return send(res, 200, { flags: db.flags });
    if (sub.match(/^flags\/\d+$/) && m === "PUT") {
      const f = db.flags.find(x => x.id === +sub.split("/")[1]); if (!f) return send(res, 404, { error:"Not found." });
      const b = await body(req); f.done = true; f.action = b.action || "dismissed";
      if (b.action === "ban") { const t = db.users.find(x => x.id === f.fromId); if (t && t.role !== "owner") { t.suspended = true; t.tokenVer = (t.tokenVer || 0) + 1; } }
      logAdmin("Moderation: " + f.action + " — " + f.fromName); saveDB(); return send(res, 200, { flag: f });
    }
    if (sub === "ai" && m === "GET") { const n = db.news || {}; return send(res, 200, { enabled: !!GEMINI_KEY, model: goodModel || n.model || "", news: { count: (n.items||[]).length, updated: n.updated || 0, error: n.error || "", basic: !!n.basic, items: n.items || [] }, report: db.aiReport || null }); }
    if (sub === "ai/news" && m === "POST") { const r = await refreshNews("manual"); return r ? send(res, 200, { news: r }) : send(res, 502, { error: "Refresh failed: " + ((db.news||{}).error || "unknown") }); }
    if (sub === "ai/report" && m === "POST") { if (!GEMINI_KEY) return send(res, 400, { error: "Add GEMINI_API_KEY on Render first." }); try { return send(res, 200, { report: await ownerReport() }); } catch (e) { return send(res, 502, { error: "AI report failed: " + e.message }); } }
    if (sub === "swatches" && m === "GET") return send(res, 200, { swatches: db.swatches });
    if (sub.match(/^swatches\/\d+$/)) {
      const x = db.swatches.find(y => y.id === +sub.split("/")[1]); if (!x) return send(res, 404, { error:"Not found." });
      if (m === "DELETE") { db.swatches = db.swatches.filter(y => y !== x); saveDB(); return send(res, 200, { ok:true }); }
      const b = await body(req); if (["new","contacted","sent","closed"].includes(b.status)) x.status = b.status; if (b.adminNote !== undefined) x.adminNote = clean(b.adminNote, 300);
      saveDB(); return send(res, 200, { swatch: x });
    }
    if (sub === "submissions" && m === "GET") return send(res, 200, { submissions: db.submissions });
    if (sub.match(/^submissions\/\d+$/)) {
      const x = db.submissions.find(y => y.id === +sub.split("/")[1]); if (!x) return send(res, 404, { error:"Not found." });
      if (m === "DELETE") { db.submissions = db.submissions.filter(y => y !== x); saveDB(); return send(res, 200, { ok:true }); }
      const b = await body(req);
      if (b.action === "publish") {
        const price = parseFloat(String(b.price ?? x.price).replace(",", ".")) || 0;
        const l = { id: nextId("listing"), ownerId: u.id, displaySeller: x.shop, displayVerified: !!b.verified, title: clean(b.title || x.title || (x.type + " fabric"), 120), type: clean(b.type || x.type, 40),
          comp: clean(b.comp, 80), gsm: +(b.gsm ?? x.gsm) || 0, width: +(b.width ?? x.width) || 0, price, moq: Math.max(1, +(b.moq ?? x.moq) || 1), origin: clean(b.origin || x.market, 80),
          cert: "", color: "#cdbfa6", img: x.photos[0] || "", inco: "FOB", stock: "in stock", lead: 7, featured: false, fromSubmission: x.id, createdAt: now() };
        db.listings.unshift(l); x.status = "published"; x.listingId = l.id; logAdmin("Published submission from " + x.shop); saveDB();
        return send(res, 200, { listing: listingOut(l), submission: x });
      }
      if (["new","contacted","rejected"].includes(b.status)) x.status = b.status; saveDB(); return send(res, 200, { submission: x });
    }
    if (sub === "stats" && m === "GET") {
      const days = []; for (let i = 29; i >= 0; i--) { const d = new Date(now() - i * 864e5).toISOString().slice(0, 10); const st = db.stats[d] || { views:0, visitors:0, pages:{} };
        const inDay = t => t && new Date(t).toISOString().slice(0, 10) === d;
        days.push({ day: d, views: st.views, visitors: st.visitors, pages: st.pages, signups: db.users.filter(x => inDay(x.createdAt) && !x.seed).length, waitlist: db.waitlist.filter(x => inDay(x.createdAt)).length,
          swatches: db.swatches.filter(x => inDay(x.createdAt)).length, submissions: db.submissions.filter(x => inDay(x.createdAt)).length, rfqs: db.rfqs.filter(x => inDay(x.createdAt)).length }); }
      return send(res, 200, { days, totals: { users: db.users.filter(x => !x.seed).length, listings: db.listings.length, waitlist: db.waitlist.length, swatches: db.swatches.length, submissions: db.submissions.length },
        services: { email: !!RESEND_KEY, images: USE_CLD } });
    }
    if (sub === "migrate-images" && m === "POST") {
      if (!USE_CLD) return send(res, 400, { error:"Add the Cloudinary settings on Render first." });
      let moved = 0, failed = 0;
      for (const l of db.listings) { if (isDataImage(l.img)) { try { l.img = await storeImage(l.img, "listings"); moved++; } catch { failed++; } } }
      for (const x of db.submissions) { for (let i = 0; i < x.photos.length; i++) if (isDataImage(x.photos[i])) { try { x.photos[i] = await storeImage(x.photos[i], "submissions"); moved++; } catch { failed++; } } }
      logAdmin("Moved " + moved + " photos to Cloudinary" + (failed ? " (" + failed + " failed)" : "")); saveDB();
      return send(res, 200, { moved, failed });
    }
    if (sub === "waitlist" && m === "GET") return send(res, 200, { waitlist: db.waitlist.map(w => ({ ...w, unsubscribe: PUBLIC_URL + "/api/waitlist/unsubscribe?e=" + encodeURIComponent(w.email) + "&t=" + unsubToken(w.email) })) });
    if (sub.match(/^waitlist\/\d+$/) && m === "DELETE") { const id = +sub.split("/")[1]; const w = db.waitlist.find(x => x.id === id); if (!w) return send(res, 404, { error:"Not found." }); db.waitlist = db.waitlist.filter(x => x !== w); logAdmin("Removed from waitlist: " + w.email); saveDB(); return send(res, 200, { ok:true }); }
    if (sub === "settings" && m === "GET") return send(res, 200, { settings: S });
    if (sub === "settings" && m === "PUT") {
      const b = await body(req);
      ["commission","boostFee","sampleFee"].forEach(k => { if (b[k] !== undefined) S[k] = +b[k]; });
      ["requireVerify","maintenance","autoFlag","prelaunch"].forEach(k => { if (b[k] !== undefined) S[k] = !!b[k]; });
      if (b.launchText !== undefined) S.launchText = String(b.launchText).slice(0, 40);
      if (b.announcement !== undefined) S.announcement = String(b.announcement).slice(0, 300);
      logAdmin("Settings updated " + JSON.stringify(b)); saveDB(); return send(res, 200, { settings: S });
    }
    if (sub === "export" && m === "GET") { const { secret, ...rest } = db; return send(res, 200, { ...rest, users: db.users.map(pub) }); }
    return send(res, 404, { error:"Unknown admin endpoint." });
  }

  return send(res, 404, { error:"Unknown endpoint." });
}
function unitPrice(l, qty){ const tiers = [[l.moq, l.price],[l.moq*5, +(l.price*0.92).toFixed(2)],[l.moq*20, +(l.price*0.85).toFixed(2)]]; let p = l.price; tiers.forEach(([min, pr]) => { if (qty >= min) p = pr; }); return p; }

/* ---------- static frontend ---------- */
const MIME = { ".html":"text/html; charset=utf-8", ".js":"text/javascript", ".css":"text/css", ".png":"image/png", ".jpg":"image/jpeg", ".svg":"image/svg+xml", ".ico":"image/x-icon", ".json":"application/json" };
function serveStatic(req, res, url){
  let file = url.pathname === "/" ? "/index.html" : url.pathname;
  const full = path.join(PUBLIC, path.normalize(file).replace(/^(\.\.[/\\])+/, ""));
  if (!full.startsWith(PUBLIC)) return send(res, 403, { error:"Forbidden" });
  fs.readFile(full, (err, data) => {
    if (err) return fs.readFile(path.join(PUBLIC, "index.html"), (e2, d2) => e2 ? send(res, 404, { error:"Not found" }) : (res.writeHead(200, { "Content-Type":"text/html; charset=utf-8" }), res.end(d2)));
    res.writeHead(200, { "Content-Type": MIME[path.extname(full)] || "application/octet-stream" }); res.end(data);
  });
}

initDB().then(() => {
  http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname.startsWith("/api/")) return api(req, res, url).catch(e => send(res, 500, { error: String(e) }));
    serveStatic(req, res, url);
  }).listen(PORT, () => console.log(`FabriTrade server running →  http://localhost:${PORT}  (storage: ${USE_UPSTASH ? "Upstash cloud" : DATA_FILE})  (AI: ${GEMINI_KEY ? "Gemini on" : "off — add GEMINI_API_KEY"})`));
  // keep Price Watch fresh while the server is awake (it also refreshes when someone opens the page)
  { const prune = () => { const t = now(), a = db.swatches.length + db.submissions.length;
      db.swatches = db.swatches.filter(x => t - x.createdAt < 365 * 864e5);
      db.submissions = db.submissions.filter(x => x.status === "published" || t - x.createdAt < 183 * 864e5);
      for (const u of db.users) if (u.resetExp && u.resetExp < t) { delete u.resetHash; delete u.resetExp; }
      if (db.swatches.length + db.submissions.length !== a) { logAdmin("Removed old swatch requests / submissions (privacy policy retention)"); saveDB(); } };
    prune(); setInterval(prune, 24 * 3600e3).unref(); }
  { if (newsStale()) refreshNews("startup"); setInterval(() => { if (newsStale()) refreshNews("scheduled"); }, 30 * 60e3).unref(); }
});
// save any last changes before Render shuts the server down
process.on("SIGTERM", async () => { if (USE_UPSTASH) { clearTimeout(cloudTimer); try { await upstash(["SET", UP_KEY, JSON.stringify(db)]); } catch {} } process.exit(0); });

/* ---------- demo seed (sellers + fabrics so the shop isn't empty) ---------- */
function seed(){
  const mk = (name, email, country) => { const { salt, hash } = hashPassword("password"); const u = { id: nextId("user"), name, email, salt, hash, role:"seller", verified:true, suspended:false, country, seed:true, createdAt: now() }; db.users.push(u); return u; };
  const s1 = mk("Nam Phong Textiles", "namphong@example.com", "VN"), s2 = mk("Silk Road Mills", "silkroad@example.com", "CN"), s3 = mk("Mekong Linen House", "mekong@example.com", "VN"), s4 = mk("Pearl River Denim Co.", "pearlriver@example.com", "CN");
  const L = (ownerId, o) => db.listings.push({ id: nextId("listing"), ownerId, rating:4.8, inco:"FOB", stock:"in stock", lead:7, featured:false, createdAt: now(), ...o });
  L(s1.id, { title:"Combed Cotton Jersey 180 GSM", type:"Cotton", comp:"100% Cotton", gsm:180, width:180, price:3.2, moq:50, origin:"Nam Định, Vietnam", cert:"OEKO-TEX", color:"#e8e2d4", img:"https://loremflickr.com/600/450/cotton,fabric?lock=101", featured:true });
  L(s1.id, { title:"Cotton Poplin Shirting 120 GSM", type:"Cotton", comp:"100% Cotton", gsm:120, width:145, price:2.9, moq:50, origin:"Thái Bình, Vietnam", cert:"OEKO-TEX", color:"#dfe7ee", img:"https://loremflickr.com/600/450/cotton,shirt,textile?lock=107" });
  L(s2.id, { title:"Mulberry Silk Charmeuse 19mm", type:"Silk", comp:"100% Mulberry Silk", gsm:88, width:114, price:18.5, moq:20, origin:"Hangzhou, China", cert:"OEKO-TEX", color:"#d8b08c", img:"https://loremflickr.com/600/450/silk,fabric?lock=103", rating:4.9, featured:true });
  L(s4.id, { title:"Stretch Denim 12oz Indigo", type:"Denim", comp:"98% Cotton 2% Spandex", gsm:340, width:150, price:5.6, moq:200, origin:"Foshan, China", cert:"", color:"#33415c", img:"https://loremflickr.com/600/450/denim,jeans?lock=102", inco:"CIF", lead:14 });
  L(s3.id, { title:"Washed Linen 165 GSM Natural", type:"Linen", comp:"100% Linen", gsm:165, width:140, price:7.8, moq:30, origin:"Hải Dương, Vietnam", cert:"GOTS", color:"#cdbfa6", img:"https://loremflickr.com/600/450/linen,fabric?lock=104" });
  L(s1.id, { title:"Recycled Poly Fleece 280 GSM", type:"Polyester", comp:"100% Recycled Polyester", gsm:280, width:165, price:4.1, moq:100, origin:"Bình Dương, Vietnam", cert:"GRS", color:"#6b7c93", img:"https://loremflickr.com/600/450/fleece,fabric?lock=105", lead:12 });
  db.rfqs.push({ id: nextId("rfq"), byId: 0, by:"Lemaire Studio (FR)", title:"Organic cotton jersey 180 GSM", type:"Cotton", qty:2000, budget:3.5, notes:"GOTS preferred, white", offers:[{ sellerId:s1.id, seller:s1.name, price:3.2, at: now() }], closed:false, createdAt: now() });
}
