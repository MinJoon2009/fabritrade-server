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
const DATA_FILE = path.join(__dirname, "data.json");
const PUBLIC = path.join(__dirname, "public");

/* ---------- database ---------- */
let db;
function loadDB(){ try { return JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); } catch { return null; } }
function saveDB(){ fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
db = loadDB();
if (!db) {
  db = {
    secret: crypto.randomBytes(32).toString("hex"),
    seq: { user:0, listing:0, order:0, message:0, rfq:0, flag:0 },
    settings: { commission:3.5, boostFee:9.99, sampleFee:5, requireVerify:false, maintenance:false, announcement:"", autoFlag:true },
    revenue: { commission:0, boosts:0 },
    users:[], listings:[], orders:[], messages:[], rfqs:[], flags:[], log:[],
  };
  seed(); saveDB();
}
// backfill for older data files
db.settings = Object.assign({ commission:3.5, boostFee:9.99, sampleFee:5, requireVerify:false, maintenance:false, announcement:"", autoFlag:true }, db.settings||{});
db.revenue = db.revenue || { commission:0, boosts:0 };
["rfqs","flags","log"].forEach(k=>{ if(!Array.isArray(db[k])) db[k]=[]; });
["rfq","flag"].forEach(k=>{ if(!db.seq[k]) db.seq[k]=0; });
if (!db.users.some(u=>u.role==="owner")) { /* first real signup will become owner */ }

function nextId(k){ return (db.seq[k] = (db.seq[k]||0) + 1); }
function now(){ return Date.now(); }
function COMM(){ return (+db.settings.commission || 3.5) / 100; }
function logAdmin(msg){ db.log.unshift({ t: now(), m: msg }); db.log = db.log.slice(0, 300); }

/* ---------- auth helpers ---------- */
function hashPassword(password, salt){ salt = salt || crypto.randomBytes(16).toString("hex"); return { salt, hash: crypto.scryptSync(password, salt, 64).toString("hex") }; }
function checkPassword(p, salt, hash){ try { return crypto.timingSafeEqual(Buffer.from(crypto.scryptSync(p, salt, 64).toString("hex")), Buffer.from(hash)); } catch { return false; } }
function makeToken(id){ const body = id + "." + now(); const sig = crypto.createHmac("sha256", db.secret).update(body).digest("hex"); return Buffer.from(body + "." + sig).toString("base64"); }
function userFromToken(tok){ try { const [id, ts, sig] = Buffer.from(tok, "base64").toString("utf8").split("."); const ok = crypto.createHmac("sha256", db.secret).update(id + "." + ts).digest("hex") === sig; return ok ? db.users.find(u => u.id === +id) || null : null; } catch { return null; } }
const pub = u => u && ({ id:u.id, name:u.name, email:u.email, role:u.role, verified:!!u.verified, suspended:!!u.suspended, country:u.country||"" });

/* ---------- http helpers ---------- */
function cors(res){ res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization"); res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS"); }
function send(res, code, obj){ cors(res); res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); }
function body(req){ return new Promise(r => { let d = ""; req.on("data", c => { d += c; if (d.length > 8e6) req.destroy(); }); req.on("end", () => { try { r(d ? JSON.parse(d) : {}); } catch { r({}); } }); }); }
function auth(req){ return userFromToken((req.headers["authorization"]||"").replace(/^Bearer\s+/i, "")); }
function listingOut(l){ const s = db.users.find(u => u.id === l.ownerId); return { ...l, sellerName: s ? s.name : "Unknown", sellerVerified: !!(s && s.verified), rating: l.rating || 4.8, trades: db.orders.filter(o => o.sellerId === l.ownerId && o.status !== "refunded").length }; }

/* ---------- AI scam flagging (rule-based; swap for an AI API later) ---------- */
const RISKY = ["bank wire","bank transfer","wire transfer","western union","whatsapp","wechat","telegram","zalo","paypal","off platform","off-platform","offline","skip the fee","skip the platform","account number","iban","转账","银行","线下","微信","私下","chuyển khoản","ngoài nền tảng","ngân hàng"];
function riskReason(text){ const s = String(text).toLowerCase(); const hit = RISKY.find(w => s.includes(w)); return hit ? "Off-platform payment / contact attempt (\"" + hit + "\")" : null; }

/* ================= API ================= */
async function api(req, res, url){
  const p = url.pathname, m = req.method;
  if (m === "OPTIONS") { cors(res); res.writeHead(204); return res.end(); }
  const S = db.settings;

  /* ---- public ---- */
  if (p === "/api/health") return send(res, 200, { ok:true, mode:"live", maintenance:S.maintenance, announcement:S.announcement, commission:S.commission, boostFee:S.boostFee, sampleFee:S.sampleFee });
  if (p === "/api/stats") {
    const done = db.orders.filter(o => o.status !== "refunded");
    return send(res, 200, { users: db.users.length, listings: db.listings.length, orders: done.length, gmv: +done.reduce((s,o)=>s+o.total,0).toFixed(2), countries: 50 });
  }

  /* ---- auth ---- */
  if (p === "/api/register" && m === "POST") {
    const b = await body(req);
    if (!b.email || !b.password || !b.name) return send(res, 400, { error:"Name, email and password are required." });
    if (String(b.password).length < 6) return send(res, 400, { error:"Password must be at least 6 characters." });
    const email = String(b.email).toLowerCase().trim();
    if (db.users.some(u => u.email === email)) return send(res, 409, { error:"An account with that email already exists." });
    const { salt, hash } = hashPassword(b.password);
    // The first REAL account (not a demo seed) becomes the platform owner.
    const isFirst = !db.users.some(u => u.role === "owner") && db.users.filter(u => !u.seed).length === 0;
    const user = { id: nextId("user"), name: String(b.name).slice(0,80), email, salt, hash,
      role: isFirst ? "owner" : (b.role === "seller" ? "seller" : "buyer"), verified: isFirst, suspended:false, country: b.country||"", createdAt: now() };
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
  if (p === "/api/me") { const u = auth(req); return u ? send(res, 200, { user: pub(u) }) : send(res, 401, { error:"Not logged in." }); }

  /* ---- listings ---- */
  if (p === "/api/listings" && m === "GET") return send(res, 200, { listings: db.listings.filter(l=>!l.hidden).map(listingOut) });
  if (p.match(/^\/api\/listings\/\d+$/) && m === "GET") { const l = db.listings.find(x => x.id === +p.split("/")[3]); return l ? send(res, 200, { listing: listingOut(l) }) : send(res, 404, { error:"Not found." }); }
  if (p === "/api/listings" && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    if (S.requireVerify && !u.verified && u.role !== "owner") return send(res, 403, { error:"Your account must be verified before listing. The owner will review it soon." });
    const b = await body(req);
    const l = { id: nextId("listing"), ownerId: u.id, title: String(b.title||"Untitled fabric").slice(0,120), type: b.type||"Cotton", comp: b.comp||"", gsm:+b.gsm||0, width:+b.width||0,
      price:+b.price||0, moq: Math.max(1,+b.moq||1), origin: b.origin||"", cert: b.cert||"", color: b.color||"#cdbfa6", img: b.img||"", inco: b.inco||"FOB", stock: b.stock||"in stock", lead:+b.lead||7, rating:5.0, featured:false, createdAt: now() };
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
    l.featured = true; l.boostedAt = now(); db.revenue.boosts += +S.boostFee; saveDB();
    return send(res, 200, { listing: listingOut(l), fee: S.boostFee }); // real Stripe charge for the boost fee goes here
  }
  if (p === "/api/my/listings" && m === "GET") { const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." }); return send(res, 200, { listings: db.listings.filter(x => x.ownerId === u.id).map(listingOut) }); }

  /* ---- orders (escrow + commission) ---- */
  if (p === "/api/orders" && m === "POST") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in to buy." });
    if (S.maintenance && u.role !== "owner") return send(res, 503, { error:"The marketplace is in maintenance mode. Please try again soon." });
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
    const b = await body(req); if (!b.toId || !b.text) return send(res, 400, { error:"Recipient and text required." });
    const to = db.users.find(x => x.id === +b.toId); if (!to) return send(res, 404, { error:"Recipient not found." });
    const text = String(b.text).slice(0, 2000);
    const reason = S.autoFlag ? riskReason(text) : null;
    const msg = { id: nextId("message"), fromId: u.id, toId: to.id, listingId: +b.listingId || null, text, flagged: !!reason, createdAt: now() };
    db.messages.push(msg);
    if (reason) db.flags.unshift({ id: nextId("flag"), messageId: msg.id, fromId: u.id, fromName: u.name, toName: to.name, text, reason, at: now(), done:false });
    saveDB(); return send(res, 200, { message: { ...msg, mine:true } });
  }
  if (p === "/api/messages" && m === "GET") {
    const u = auth(req); if (!u) return send(res, 401, { error:"Please log in." });
    const w = +url.searchParams.get("withUserId");
    const msgs = db.messages.filter(x => (x.fromId===u.id && x.toId===w) || (x.fromId===w && x.toId===u.id)).sort((a,b)=>a.createdAt-b.createdAt).map(x => ({ ...x, mine: x.fromId===u.id }));
    const other = db.users.find(x => x.id === w);
    return send(res, 200, { messages: msgs, with: other ? pub(other) : null });
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
    return l ? send(res, 200, { user: pub(db.users.find(x => x.id === l.ownerId)) }) : send(res, 404, { error:"Not found." });
  }

  /* ---- OWNER / ADMIN API (used by the Manager site) ---- */
  if (p.startsWith("/api/admin/")) {
    const u = auth(req); if (!u || u.role !== "owner") return send(res, 403, { error:"Owner access only." });
    const sub = p.replace("/api/admin/", "");
    if (sub === "overview" && m === "GET") {
      const done = db.orders.filter(o => o.status !== "refunded");
      return send(res, 200, { settings: S, revenue: { commission:+db.revenue.commission.toFixed(2), boosts:+db.revenue.boosts.toFixed(2) },
        stats: { users: db.users.length, sellers: db.users.filter(x=>x.role!=="buyer").length, listings: db.listings.length, featured: db.listings.filter(x=>x.featured).length,
          orders: done.length, gmv:+done.reduce((s,o)=>s+o.total,0).toFixed(2), escrow:+db.orders.filter(o=>o.status==="in_escrow").reduce((s,o)=>s+o.total,0).toFixed(2),
          shipped: db.orders.filter(o=>o.status==="shipped").length, openRfqs: db.rfqs.filter(r=>!r.closed).length, openFlags: db.flags.filter(f=>!f.done).length, unverified: db.users.filter(x=>x.role!=="buyer"&&!x.verified).length },
        log: db.log.slice(0, 50) });
    }
    if (sub === "users" && m === "GET") return send(res, 200, { users: db.users.map(pub).map(x => ({ ...x, risk: db.flags.some(f => !f.done && f.fromId === x.id) })) });
    if (sub.match(/^users\/\d+$/)) {
      const t = db.users.find(x => x.id === +sub.split("/")[1]); if (!t) return send(res, 404, { error:"User not found." });
      if (m === "DELETE") { if (t.role === "owner") return send(res, 400, { error:"Can't delete the owner." }); db.users = db.users.filter(x => x !== t); logAdmin("Deleted user " + t.email); saveDB(); return send(res, 200, { ok:true }); }
      const b = await body(req); ["verified","suspended"].forEach(k => { if (b[k] !== undefined) t[k] = !!b[k]; }); if (b.role && ["buyer","seller"].includes(b.role) && t.role !== "owner") t.role = b.role;
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
      if (b.action === "ban") { const t = db.users.find(x => x.id === f.fromId); if (t && t.role !== "owner") t.suspended = true; }
      logAdmin("Moderation: " + f.action + " — " + f.fromName); saveDB(); return send(res, 200, { flag: f });
    }
    if (sub === "settings" && m === "GET") return send(res, 200, { settings: S });
    if (sub === "settings" && m === "PUT") {
      const b = await body(req);
      ["commission","boostFee","sampleFee"].forEach(k => { if (b[k] !== undefined) S[k] = +b[k]; });
      ["requireVerify","maintenance","autoFlag"].forEach(k => { if (b[k] !== undefined) S[k] = !!b[k]; });
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

http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname.startsWith("/api/")) return api(req, res, url).catch(e => send(res, 500, { error: String(e) }));
  serveStatic(req, res, url);
}).listen(PORT, () => console.log(`FabriTrade server running →  http://localhost:${PORT}`));

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
