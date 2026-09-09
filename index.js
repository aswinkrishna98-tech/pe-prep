require("dotenv").config();
const path = require("path");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");

const db = require("./db");
const { createOrder, verifyPaymentSignature, verifyWebhookSignature } = require("./razorpay");

const app = express();
const PORT = process.env.PORT || 4000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.warn(
    "JWT_SECRET is not set - using an insecure development default. " +
      "Set a real random JWT_SECRET in Render's environment variables before real users sign up."
  );
}
const EFFECTIVE_JWT_SECRET = JWT_SECRET || "dev-insecure-secret-change-me";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

app.use(cors({ origin: CORS_ORIGIN }));

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

    const event = JSON.parse(req.body.toString("utf8"));
    if (event.event === "payment.captured") {
      const payment = event.payload.payment.entity;
      const { userId, plan, examId } = payment.notes || {};
      if (userId && plan) {
        try {
          if (plan === "exampass" && examId) {
            await db.grantExamPass(userId, examId);
          } else {
            await db.setPlan(userId, plan);
          }
          await db.recordOrder(userId, {
            orderId: payment.order_id,
            paymentId: payment.id,
            amount: payment.amount,
            source: "webhook",
          });
          console.log(`[webhook] Activated "${plan}"${examId ? ` (${examId})` : ""} for user ${userId}`);
        } catch (e) {
          console.error("[webhook] Failed to persist plan/order:", e.message);
          return res.status(500).send("Failed to record payment");
        }
      }
    }
    res.json({ received: true });
  }
);

app.use(express.json());

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
app.post("/api/auth/signup", async (req, res) => {
  const { email, password, name, preferredExam } = req.body || {};
  const normalizedEmail = String(email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(normalizedEmail) || !password || String(password).length < 6) {
    return res.status(400).json({ error: "A valid email and a password of at least 6 characters are required" });
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

app.post("/api/auth/login", async (req, res) => {
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

app.post("/api/auth/google", async (req, res) => {
  if (!googleClient) {
    return res.status(501).json({ error: "Google sign-in isn't configured on the server yet" });
  }
  const { credential } = req.body || {};
  if (!credential) return res.status(400).json({ error: "Missing Google credential" });
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const { sub, email, name } = payload;
    const normalizedEmail = String(email || "").toLowerCase();
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
app.post("/api/create-order", async (req, res) => {
  const { userId, plan, examId } = req.body || {};
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
app.post("/api/verify-payment", async (req, res) => {
  const {
    userId,
    plan,
    examId,
    razorpay_order_id: orderId,
    razorpay_payment_id: paymentId,
    razorpay_signature: signature,
  } = req.body || {};

  if (!userId || !plan || !orderId || !paymentId || !signature) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  if (plan === "exampass" && !examId) {
    return res.status(400).json({ error: "examId is required to verify an exam pass payment" });
  }

  const valid = verifyPaymentSignature({ orderId, paymentId, signature });
  if (!valid) {
    console.warn(`Signature mismatch for user ${userId}, order ${orderId}`);
    return res.status(400).json({ error: "Payment signature verification failed" });
  }

  try {
    if (plan === "exampass") {
      await db.grantExamPass(userId, examId);
      await db.recordOrder(userId, { orderId, paymentId, source: "verify-payment" });
      const examPasses = await db.getExamPasses(userId);
      res.json({ success: true, examPasses });
    } else {
      const user = await db.setPlan(userId, plan);
      await db.recordOrder(userId, { orderId, paymentId, source: "verify-payment" });
      res.json({ success: true, plan: user.plan });
    }
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
app.post("/api/contact", async (req, res) => {
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

const fs = require("fs");
const FRONTEND_INDEX = path.join(__dirname, "index.html");
app.use(express.static(__dirname));
app.get("*", (req, res) => {
  if (fs.existsSync(FRONTEND_INDEX)) {
    res.sendFile(FRONTEND_INDEX);
  } else {
    res.status(200).json({
      status: "PE Prep payments API is running",
      note: "index.html not deployed here - this service is API-only.",
    });
  }
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
