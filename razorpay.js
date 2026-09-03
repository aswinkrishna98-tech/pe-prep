const crypto = require("crypto");
const Razorpay = require("razorpay");

const PLAN_AMOUNTS_INR = {
  pro: 49900,
  proplus: 89900,
};

function getClient() {
  const { RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET } = process.env;
  if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
    throw new Error(
      "RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are not set. Copy .env.example to .env and fill in your Razorpay test (or live) keys before calling this."
    );
  }
  return new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
}

async function createOrder({ plan, userId }) {
  const amount = PLAN_AMOUNTS_INR[plan];
  if (!amount) {
    throw new Error(`Unknown plan "${plan}". Expected "pro" or "proplus".`);
  }
  const client = getClient();
  const order = await client.orders.create({
    amount,
    currency: "INR",
    receipt: `pe-prep-${userId}-${Date.now()}`,
    notes: { userId, plan },
  });
  return order;
}

function verifyPaymentSignature({ orderId, paymentId, signature }) {
  const { RAZORPAY_KEY_SECRET } = process.env;
  const expected = crypto
    .createHmac("sha256", RAZORPAY_KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest("hex");
  return expected === signature;
}

function verifyWebhookSignature({ rawBody, signatureHeader }) {
  const { RAZORPAY_WEBHOOK_SECRET } = process.env;
  if (!RAZORPAY_WEBHOOK_SECRET) {
    throw new Error("RAZORPAY_WEBHOOK_SECRET is not set in .env");
  }
  const expected = crypto
    .createHmac("sha256", RAZORPAY_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");
  return expected === signatureHeader;
}

module.exports = { PLAN_AMOUNTS_INR, createOrder, verifyPaymentSignature, verifyWebhookSignature };

