// Run: DATABASE_URL=postgres://pe:pe@localhost/petest npm test
// Uses a stubbed Razorpay SDK (no network) and a real Postgres.
const test = require("node:test");
const assert = require("node:assert");
const crypto = require("crypto");
const Module = require("module");

process.env.PORT = "4555";
process.env.RAZORPAY_KEY_ID = "rzp_test_x";
process.env.RAZORPAY_KEY_SECRET = "secret_x";
process.env.RAZORPAY_WEBHOOK_SECRET = "whsec_x";
process.env.JWT_SECRET = "test-jwt";
process.env.CORS_ORIGIN = "https://physicaledmastery.com";
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = "postgres://pe:pe@localhost/petest";

// --- fake Razorpay SDK -------------------------------------------------------
const ORDERS = {}, PAYMENTS = {};
class FakeRazorpay {
  constructor() {
    this.orders = {
      create: async (o) => { const id = "order_" + Object.keys(ORDERS).length; ORDERS[id] = { id, ...o }; return ORDERS[id]; },
      fetch: async (id) => { if (!ORDERS[id]) throw new Error("nf"); return ORDERS[id]; },
    };
    this.payments = { fetch: async (id) => { if (!PAYMENTS[id]) throw new Error("nf"); return PAYMENTS[id]; } };
  }
}
const origLoad = Module._load;
Module._load = function (req, ...rest) { return req === "razorpay" ? FakeRazorpay : origLoad.call(this, req, ...rest); };

const BASE = "http://localhost:" + process.env.PORT;
const sign = (o, p) => crypto.createHmac("sha256", "secret_x").update(`${o}|${p}`).digest("hex");
const post = (path, body, headers = {}) =>
  fetch(BASE + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

test.before(async () => {
  const db = require("../db");
  await db.pool.query("DROP TABLE IF EXISTS orders, exam_passes, users, accounts, contact_messages CASCADE");
  require("../index");
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); return; } catch { await new Promise((r) => setTimeout(r, 100)); } }
});
process.on("beforeExit", () => {});

async function makeOrder(userId, plan, examId) {
  const r = await post("/api/create-order", { userId, plan, examId });
  assert.equal(r.status, 200);
  return (await r.json()).orderId;
}
function pay(orderId, paymentId, over = {}) {
  const o = ORDERS[orderId];
  PAYMENTS[paymentId] = { id: paymentId, order_id: orderId, status: "captured", amount: o.amount, currency: "INR", ...over };
}

test("source files are not publicly served", async () => {
  for (const f of ["/index.js", "/db.js", "/package.json", "/razorpay.js", "/.env"]) {
    const r = await fetch(BASE + f);
    assert.equal(r.status, 404, f);
  }
});

test("exam pass payment cannot be replayed as a higher plan or another user", async () => {
  const oid = await makeOrder("guest_a", "exampass", "kvs-pgt");
  pay(oid, "pay_1");
  // attacker claims proplus for someone else - extra body fields must be ignored
  const r = await post("/api/verify-payment", {
    userId: "victim", plan: "proplus", razorpay_order_id: oid, razorpay_payment_id: "pay_1", razorpay_signature: sign(oid, "pay_1"),
  });
  assert.equal(r.status, 200);
  const a = await (await fetch(BASE + "/api/plan/guest_a")).json();
  assert.deepEqual(a.examPasses, ["kvs-pgt"]);
  assert.equal(a.plan, "free");
  const v = await (await fetch(BASE + "/api/plan/victim")).json();
  assert.equal(v.plan, "free");
});

test("bad signature, wrong amount, unpaid payment are rejected", async () => {
  const oid = await makeOrder("guest_b", "pro");
  pay(oid, "pay_2");
  assert.equal((await post("/api/verify-payment", { razorpay_order_id: oid, razorpay_payment_id: "pay_2", razorpay_signature: "bad" })).status, 400);
  pay(oid, "pay_3", { amount: 100 });
  assert.equal((await post("/api/verify-payment", { razorpay_order_id: oid, razorpay_payment_id: "pay_3", razorpay_signature: sign(oid, "pay_3") })).status, 400);
  pay(oid, "pay_4", { status: "failed" });
  assert.equal((await post("/api/verify-payment", { razorpay_order_id: oid, razorpay_payment_id: "pay_4", razorpay_signature: sign(oid, "pay_4") })).status, 402);
  assert.equal((await (await fetch(BASE + "/api/plan/guest_b")).json()).plan, "free");
});

test("valid pro payment upgrades; replay is idempotent; cheaper replay never downgrades", async () => {
  const oid = await makeOrder("guest_c", "proplus");
  pay(oid, "pay_5");
  for (let i = 0; i < 2; i++) {
    const r = await post("/api/verify-payment", { razorpay_order_id: oid, razorpay_payment_id: "pay_5", razorpay_signature: sign(oid, "pay_5") });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).plan, "proplus");
  }
  const db = require("../db");
  const { rows } = await db.pool.query("SELECT count(*)::int AS n FROM orders WHERE payment_id='pay_5'");
  assert.equal(rows[0].n, 1);
  const oid2 = await makeOrder("guest_c", "pro");
  pay(oid2, "pay_6");
  await post("/api/verify-payment", { razorpay_order_id: oid2, razorpay_payment_id: "pay_6", razorpay_signature: sign(oid2, "pay_6") });
  assert.equal((await (await fetch(BASE + "/api/plan/guest_c")).json()).plan, "proplus");
});

test("webhook: signature required, duplicate delivery recorded once", async () => {
  const oid = await makeOrder("guest_d", "pro");
  const body = JSON.stringify({ event: "payment.captured", payload: { payment: { entity: { id: "pay_7", order_id: oid, amount: 49900, notes: { userId: "guest_d", plan: "pro" } } } } });
  const sig = crypto.createHmac("sha256", "whsec_x").update(body).digest("hex");
  const send = (s) => fetch(BASE + "/api/webhook", { method: "POST", headers: { "content-type": "application/json", "x-razorpay-signature": s }, body });
  assert.equal((await send("nope")).status, 400);
  assert.equal((await send(sig)).status, 200);
  assert.equal((await send(sig)).status, 200);
  const db = require("../db");
  assert.equal((await db.pool.query("SELECT count(*)::int AS n FROM orders WHERE payment_id='pay_7'")).rows[0].n, 1);
  assert.equal((await (await fetch(BASE + "/api/plan/guest_d")).json()).plan, "pro");
});

test("signed-in user: order is bound to JWT account, not the body userId", async () => {
  const s = await (await post("/api/auth/signup", { email: "t@example.com", password: "secret12", name: "T" })).json();
  const r = await post("/api/create-order", { userId: "someone_else", plan: "pro" }, { authorization: "Bearer " + s.token });
  const { orderId } = await r.json();
  assert.equal(ORDERS[orderId].notes.userId, s.user.id);
});

test("auth: short/long password rejected, rate limit kicks in, CORS restricted", async () => {
  assert.equal((await post("/api/auth/signup", { email: "a@b.co", password: "123" })).status, 400);
  assert.equal((await post("/api/auth/signup", { email: "a@b.co", password: "x".repeat(80) })).status, 400);
  const bad = await fetch(BASE + "/api/plan/x", { headers: { origin: "https://evil.example" } });
  assert.equal(bad.headers.get("access-control-allow-origin"), null);
  const ok = await fetch(BASE + "/api/plan/x", { headers: { origin: "https://physicaledmastery.com" } });
  assert.equal(ok.headers.get("access-control-allow-origin"), "https://physicaledmastery.com");
  let last;
  for (let i = 0; i < 15; i++) last = (await post("/api/auth/login", { email: "z@z.zz", password: "wrongpass" })).status;
  assert.equal(last, 429);
});

test("create-order: unknown plan or missing fields give 400, not 500", async () => {
  let r = await post("/api/create-order", { userId: "u_val", plan: "gold" });
  assert.equal(r.status, 400);
  r = await post("/api/create-order", { userId: "u_val", plan: "exampass" });
  assert.equal(r.status, 400);
  r = await post("/api/create-order", { plan: "pro" });
  assert.equal(r.status, 400);
});

test("contact form: public POST works, admin GET requires auth", async () => {
  assert.equal((await post("/api/contact", { message: "hello" })).status, 200);
  assert.equal((await fetch(BASE + "/api/contact")).status, 401);
});

test("play billing: verifies token with Google, grants once, blocks reuse by another account", async () => {
  const play = require("../play");
  let acks = 0;
  const TOKENS = { tok_pro: { purchaseState: 0, acknowledgementState: 0, orderId: "GPA.1" }, tok_pending: { purchaseState: 2 }, tok_pass: { purchaseState: 0, acknowledgementState: 1, orderId: "GPA.2" } };
  play.fetchPurchase = async (productId, token) => {
    if (!TOKENS[token]) throw Object.assign(new Error("Purchase not found"), { status: 402 });
    return { purchase: TOKENS[token], accessToken: "x" };
  };
  play.acknowledge = async () => { acks++; };
  const db = require("../db");
  const jwt = require("jsonwebtoken");
  const mk = async (email) => jwt.sign({ sub: (await db.createAccount({ email, name: "P" })).id }, "test-jwt");
  const a = await mk("play-a@example.com"), b = await mk("play-b@example.com");
  const H = (t) => ({ Authorization: "Bearer " + t, "X-Forwarded-For": "198.51.100." + Math.floor(Math.random() * 250) });
  // not signed in / bad input
  assert.equal((await post("/api/play/verify", { productId: "pro", purchaseToken: "tok_pro" })).status, 401);
  assert.equal((await post("/api/play/verify", { productId: "gold", purchaseToken: "tok_pro" }, H(a))).status, 400);
  assert.equal((await post("/api/play/verify", { productId: "pass_nope", purchaseToken: "tok_pass" }, H(a))).status, 400);
  // unknown token and pending purchase grant nothing
  assert.equal((await post("/api/play/verify", { productId: "pro", purchaseToken: "tok_missing" }, H(a))).status, 402);
  assert.equal((await post("/api/play/verify", { productId: "pro", purchaseToken: "tok_pending" }, H(a))).status, 402);
  // a paid token grants the plan and is acknowledged
  let r = await post("/api/play/verify", { productId: "pro", purchaseToken: "tok_pro" }, H(a));
  assert.equal(r.status, 200);
  assert.equal((await r.json()).plan, "pro");
  assert.equal(acks, 1);
  // same account may re-send (restore), another account may not reuse the token
  assert.equal((await post("/api/play/verify", { productId: "pro", purchaseToken: "tok_pro" }, H(a))).status, 200);
  assert.equal((await post("/api/play/verify", { productId: "pro", purchaseToken: "tok_pro" }, H(b))).status, 409);
  // exam pass
  r = await post("/api/play/verify", { productId: "pass_ugc_net", purchaseToken: "tok_pass" }, H(b));
  assert.equal(r.status, 200);
  assert.deepEqual((await r.json()).examPasses, ["ugc-net"]);
});

test("teardown", () => { setTimeout(() => process.exit(process.exitCode || 0), 200); });
