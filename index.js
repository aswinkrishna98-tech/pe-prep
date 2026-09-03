require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");

const db = require("./db");
const { createOrder, verifyPaymentSignature, verifyWebhookSignature } = require("./razorpay");

const app = express();
const PORT = process.env.PORT || 4000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

app.use(cors({ origin: CORS_ORIGIN }));

app.post(
  "/api/webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
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
      const { userId, plan } = payment.notes || {};
      if (userId && plan) {
        db.setPlan(userId, plan);
        db.recordOrder(userId, {
          orderId: payment.order_id,
          paymentId: payment.id,
          amount: payment.amount,
          source: "webhook",
        });
        console.log(`[webhook] Activated "${plan}" for user ${userId}`);
      }
    }
    res.json({ received: true });
  }
);

app.use(express.json());

app.get("/api/plan/:userId", (req, res) => {
  const user = db.getUser(req.params.userId);
  res.json({ plan: user.plan });
});

app.post("/api/create-order", async (req, res) => {
  const { userId, plan } = req.body || {};
  if (!userId || !plan) {
    return res.status(400).json({ error: "userId and plan are required" });
  }
  try {
    const order = await createOrder({ plan, userId });
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

app.post("/api/verify-payment", (req, res) => {
  const {
    userId,
    plan,
    razorpay_order_id: orderId,
    razorpay_payment_id: paymentId,
    razorpay_signature: signature,
  } = req.body || {};

  if (!userId || !plan || !orderId || !paymentId || !signature) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const valid = verifyPaymentSignature({ orderId, paymentId, signature });
  if (!valid) {
    console.warn(`Signature mismatch for user ${userId}, order ${orderId}`);
    return res.status(400).json({ error: "Payment signature verification failed" });
  }

  const user = db.setPlan(userId, plan);
  db.recordOrder(userId, { orderId, paymentId, source: "verify-payment" });
  res.json({ success: true, plan: user.plan });
});

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

app.listen(PORT, () => {
  console.log(`PE Prep server listening on http://localhost:${PORT}`);
  if (!process.env.RAZORPAY_KEY_ID) {
    console.warn("RAZORPAY_KEY_ID is not set - set it in Render's environment variables.");
  }
});

