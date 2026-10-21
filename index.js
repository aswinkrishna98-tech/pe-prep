require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");

const db = require("./db");
const crypto = require("crypto");
const { createOrder, confirmPayment, expectedAmount, verifyWebhookSignature } = require("./razorpay");

const app = express();
const PORT = process.env.PORT || 4000;
// Render sits behind a proxy; trust one hop so req.ip is the real client.
app.set("trust proxy", 1);
// CORS: an explicit allowlist instead of "*". CORS_ORIGIN may be a
// comma-separated list; the default is the production site (+ localhost for dev).
const CORS_ORIGINS = (process.env.CORS_ORIGIN ||
  "https://physicaledmastery.com,https://www.physicaledmastery.com,http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000")
  .split(",").map((o) => o.trim()).filter(Boolean);

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error(
    "JWT_SECRET is not set - using a random per-process secret, so every restart signs all users out. " +
      "Set a real random JWT_SECRET in Render's environment variables."
  );
}
// Never fall back to a publicly-known string: that would let anyone forge a login.
const EFFECTIVE_JWT_SECRET = JWT_SECRET || crypto.randomBytes(48).toString("hex");
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin || CORS_ORIGINS.includes("*") || CORS_ORIGINS.includes(origin)),
  })
);

// Minimal in-memory fixed-window rate limiter (no extra dependency). Good
// enough to blunt credential-stuffing and contact-form spam on one instance.
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, windowMs).unref();
  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    const entry = hits.get(key);
    if (!entry || entry.reset <= now) {
      hits.set(key, { count: 1, reset: now + windowMs });
      return next();
    }
    entry.count++;
    if (entry.count > max) {
      res.set("Retry-After", String(Math.ceil((entry.reset - now) / 1000)));
      return res.status(429).json({ error: "Too many requests - please wait a minute and try again." });
    }
    next();
  };
}
const authLimiter = rateLimit({ windowMs: 60_000, max: 10 });
const contactLimiter = rateLimit({ windowMs: 10 * 60_000, max: 5 });
const orderLimiter = rateLimit({ windowMs: 60_000, max: 20 });

// Fulfils a CONFIRMED payment exactly once. Safe to call from both the
// browser flow and the webhook: a payment id that is already recorded is a
// no-op, and a plan is only ever raised, never lowered.
async function fulfilPayment({ userId, plan, examId, orderId, paymentId, amount }, source) {
  if (!(await db.hasPayment(paymentId))) {
    if (plan === "exampass") await db.grantExamPass(userId, examId);
    else await db.setPlanAtLeast(userId, plan);
    await db.recordOrder(userId, { orderId, paymentId, amount, source });
  }
  return db.getUser(userId);
}

app.post(
  "/api/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const signatureHeader = req.headers["x-razorpay-signature"];
    let valid = false;
    try {
      valid = verifyWebhookSignature({ rawBody: req.body, signatureHeader });
    } catch (e) {
      console.error("Webhook verification error:", e.message);
      return res.status(500).send("Webhook not configured");
    }
    if (!valid) {
      console.warn("Webhook signature mismatch - ignoring request");
      return res.status(400).send("Invalid signature");
    }

    let event;
    try {
      event = JSON.parse(req.body.toString("utf8"));
    } catch (e) {
      return res.status(400).send("Bad payload");
    }
    if (event.event === "payment.captured") {
      const payment = event.payload.payment.entity;
      const { userId, plan, examId } = payment.notes || {};
      const want = expectedAmount(plan);
      if (userId && plan && want && payment.amount === want && (plan !== "exampass" || examId)) {
        try {
          await fulfilPayment(
            { userId, plan, examId, orderId: payment.order_id, paymentId: payment.id, amount: payment.amount },
            "webhook"
          );
          console.log(`[webhook] Activated "${plan}"${examId ? ` (${examId})` : ""} for user ${userId}`);
        } catch (e) {
          console.error("[webhook] Failed to persist plan/order:", e.message);
          return res.status(500).send("Failed to record payment");
        }
      } else {
        console.warn("[webhook] Ignoring payment.captured with missing/mismatched notes or amount:", payment.id);
      }
    }
    res.json({ received: true });
  }
);

app.use(express.json({ limit: "100kb" }));

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------
function signToken(accountId) {
  return jwt.sign({ sub: accountId }, EFFECTIVE_JWT_SECRET, { expiresIn: "180d" });
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Not signed in" });
  try {
    const payload = jwt.verify(token, EFFECTIVE_JWT_SECRET);
    req.accountId = payload.sub;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Session expired - please sign in again" });
  }
}

// The site's admin dashboard is restricted to these accounts (matched by
// their signed-in email) - keep this in sync with ADMIN_EMAILS in the
// frontend's app-01-core.jsx. Unlike a shared client-side key, this can't be
// extracted from the shipped JS bundle: it's checked against the real,
// server-verified JWT identity of whoever is calling.
const ADMIN_EMAILS = ["aswinkrishna98@gmail.com"];
async function requireAdmin(req, res, next) {
  requireAuth(req, res, async () => {
    try {
      const account = await db.getAccountById(req.accountId);
      if (!account || !ADMIN_EMAILS.includes(String(account.email || "").toLowerCase())) {
        return res.status(403).json({ error: "Forbidden" });
      }
      next();
    } catch (e) {
      res.status(500).json({ error: "Could not verify admin access" });
    }
  });
}

async function accountWithPlan(account) {
  const userRow = await db.getUser(account.id);
  return { ...account, plan: userRow.plan, examPasses: userRow.examPasses || [] };
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
app.post("/api/auth/signup", authLimiter, async (req, res) => {
  const { email, password, name, preferredExam } = req.body || {};
  const normalizedEmail = String(email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(normalizedEmail) || !password || String(password).length < 6 || String(password).length > 72) {
    return res.status(400).json({ error: "A valid email and a password of 6-72 characters are required" });
  }
  try {
    const existing = await db.getAccountByEmail(normalizedEmail);
    if (existing) {
      return res.status(409).json({ error: "An account with this email already exists — try signing in instead." });
    }
    const passwordHash = await bcrypt.hash(String(password), 10);
    const account = await db.createAccount({ email: normalizedEmail, passwordHash, name, preferredExam: preferredExam || null });
    const token = signToken(account.id);
    res.json({ token, user: await accountWithPlan(account) });
  } catch (e) {
    console.error("signup failed:", e.message);
    res.status(500).json({ error: "Could not create account — please try again." });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = String(email || "").trim().toLowerCase();
  if (!normalizedEmail || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  try {
    const account = await db.getAccountByEmail(normalizedEmail);
    if (!account || !account.passwordHash) {
      return res.status(401).json({ error: "Incorrect email or password" });
    }
    const ok = await bcrypt.compare(String(password), account.passwordHash);
    if (!ok) return res.status(401).json({ error: "Incorrect email or password" });
    delete account.passwordHash;
    const token = signToken(account.id);
    res.json({ token, user: await accountWithPlan(account) });
  } catch (e) {
    console.error("login failed:", e.message);
    res.status(500).json({ error: "Login failed — please try again." });
  }
});

app.post("/api/auth/google", authLimiter, async (req, res) => {
  if (!googleClient) {
    return res.status(501).json({ error: "Google sign-in isn't configured on the server yet" });
  }
  const { credential } = req.body || {};
  if (!credential) return res.status(400).json({ error: "Missing Google credential" });
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const { sub, email, name, email_verified: emailVerified } = payload;
    const normalizedEmail = String(email || "").toLowerCase();
    if (!normalizedEmail || emailVerified !== true) {
      return res.status(401).json({ error: "Your Google email address is not verified." });
    }
    let account = await db.getAccountByGoogleSub(sub);
    if (!account) {
      const byEmail = await db.getAccountByEmail(normalizedEmail);
      if (byEmail) {
        await db.linkGoogleSub(byEmail.id, sub);
        account = await db.getAccountById(byEmail.id);
      } else {
        account = await db.createAccount({ email: normalizedEmail, googleSub: sub, name });
      }
    }
    const token = signToken(account.id);
    res.json({ token, user: await accountWithPlan(account) });
  } catch (e) {
    console.error("google auth failed:", e.message);
    res.status(401).json({ error: "Google sign-in failed — please try again." });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    const account = await db.getAccountById(req.accountId);
    if (!account) return res.status(404).json({ error: "Account not found" });
    res.json({ user: await accountWithPlan(account) });
  } catch (e) {
    console.error("auth/me failed:", e.message);
    res.status(500).json({ error: "Could not load account" });
  }
});

app.put("/api/profile", requireAuth, async (req, res) => {
  try {
    const account = await db.updateAccountProfile(req.accountId, req.body || {});
    res.json({ user: await accountWithPlan(account) });
  } catch (e) {
    console.error("profile update failed:", e.message);
    res.status(500).json({ error: "Could not save profile" });
  }
});

// ---------------------------------------------------------------------------
// Payments routes (unchanged — a signed-in user's account id doubles as
// their payments userId, so these work the same for guests and accounts)
// ---------------------------------------------------------------------------
app.get("/api/plan/:userId", async (req, res) => {
  try {
    const user = await db.getUser(req.params.userId);
    res.json({ plan: user.plan, examPasses: user.examPasses || [] });
  } catch (e) {
    console.error("plan lookup failed:", e.message);
    res.status(500).json({ error: "Could not look up plan" });
  }
});
// If the caller is signed in, the order is bound to their verified account id,
// whatever userId the browser sent. Guests keep their local id (as before).
function optionalAuth(req, _res, next) {
  const header = req.headers.authorization || "";
  if (header.startsWith("Bearer ")) {
    try {
      req.accountId = jwt.verify(header.slice(7), EFFECTIVE_JWT_SECRET).sub;
    } catch (e) {
      /* invalid token: treat as guest */
    }
  }
  next();
}
app.post("/api/create-order", orderLimiter, optionalAuth, async (req, res) => {
  const { plan, examId } = req.body || {};
  const userId = req.accountId || (req.body || {}).userId;
  if (!userId || !plan) {
    return res.status(400).json({ error: "userId and plan are required" });
  }
  if (plan === "exampass" && !examId) {
    return res.status(400).json({ error: "examId is required to buy an exam pass" });
  }
  try {
    const order = await createOrder({ plan, userId, examId });
    res.json({
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID,
    });
  } catch (e) {
    const message =
      e?.message ||
      e?.error?.description ||
      (typeof e === "string" ? e : null) ||
      "Order creation failed - check RAZORPAY_KEY_ID/SECRET and server network access.";
    console.error("create-order failed:", message, e);
    res.status(500).json({ error: message });
  }
});
app.post("/api/verify-payment", orderLimiter, async (req, res) => {
  const {
    razorpay_order_id: orderId,
    razorpay_payment_id: paymentId,
    razorpay_signature: signature,
  } = req.body || {};

  if (!orderId || !paymentId || !signature) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  let confirmed;
  try {
    // userId / plan / examId come from Razorpay's own order record, NOT from
    // the request body - the browser cannot choose what it is paying for.
    confirmed = await confirmPayment({ orderId, paymentId, signature });
  } catch (e) {
    console.warn(`verify-payment rejected for order ${orderId}: ${e.message}`);
    return res.status(e.status || 500).json({ error: e.message });
  }

  try {
    const user = await fulfilPayment(confirmed, "verify-payment");
    if (confirmed.plan === "exampass") res.json({ success: true, examPasses: user.examPasses });
    else res.json({ success: true, plan: user.plan });
  } catch (e) {
    console.error("verify-payment failed to persist:", e.message);
    res.status(500).json({ error: "Payment verified but could not be saved - contact support." });
  }
});
// ---------------------------------------------------------------------------
// Contact form. Public POST so any visitor can reach out; GET is read-only
// and requires a valid signed-in session for one of ADMIN_EMAILS (see
// requireAdmin above) — no personal contact info of the site owner is
// published anywhere on the site itself.
// ---------------------------------------------------------------------------
const CONTACT_MESSAGE_MAX = 4000;
app.post("/api/contact", contactLimiter, async (req, res) => {
  const { name, email, message } = req.body || {};
  const trimmedMessage = String(message || "").trim();
  if (!trimmedMessage) {
    return res.status(400).json({ error: "Message is required" });
  }
  if (trimmedMessage.length > CONTACT_MESSAGE_MAX) {
    return res.status(400).json({ error: "Message is too long" });
  }
  if (email && !EMAIL_RE.test(String(email).trim())) {
    return res.status(400).json({ error: "That email address doesn't look valid" });
  }
  try {
    await db.createContactMessage({
      name: name ? String(name).trim().slice(0, 120) : null,
      email: email ? String(email).trim().toLowerCase() : null,
      message: trimmedMessage,
    });
    res.json({ success: true });
  } catch (e) {
    console.error("contact message failed to save:", e.message);
    res.status(500).json({ error: "Could not send your message - please try again." });
  }
});
app.get("/api/contact", requireAdmin, async (req, res) => {
  try {
    const messages = await db.listContactMessages();
    res.json({ messages });
  } catch (e) {
    console.error("listing contact messages failed:", e.message);
    res.status(500).json({ error: "Could not load messages" });
  }
});

// This service is API-only. It must NOT serve its own directory (that would
// publish index.js, db.js, package.json ... to the internet).
app.get("/", (req, res) => {
  res.status(200).json({ status: "PE Prep API is running" });
});
app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

db.ensureSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`PE Prep server listening on http://localhost:${PORT}`);
      if (!process.env.RAZORPAY_KEY_ID) {
        console.warn(
          "RAZORPAY_KEY_ID is not set - copy .env.example to .env and add your keys, " +
            "or payment endpoints will fail. See server/README.md."
        );
      }
    });
  })
  .catch((e) => {
    console.error("Failed to initialize database schema - check DATABASE_URL:", e.message);
    process.exit(1);
  });
