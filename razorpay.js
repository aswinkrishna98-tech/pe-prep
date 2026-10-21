const crypto = require("crypto");
const Razorpay = require("razorpay");

const PLAN_AMOUNTS_INR = {
  pro: 49900,
  proplus: 89900,
};

// A single-exam pass ("KVS Pass" etc.) — full Pro-level access (unlimited
// mock tests, full result analysis, previous year papers) for one exam only,
// priced well below the flat Pro tier since most aspirants only care about
// one exam at a time.
const EXAM_PASS_PRICE_INR = 14900; // ₹149

function safeEqual(a, b) {
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function getClient() {
  const { RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET } = process.env;
  if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
    throw new Error(
      "RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are not set. Copy .env.example to .env and fill in your Razorpay test (or live) keys before calling this."
    );
  }
  return new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
}

// Razorpay caps `receipt` at a small fixed length (observed: rejects anything
// over 56 chars). `userId` used to always be a short guest-generated id
// ("u_abc123..."), so `pe-prep-${userId}-${Date.now()}` fit comfortably - but
// a signed-in account's id is a full UUID (36 chars), which pushes that same
// template past the limit and makes every checkout for a signed-in user fail
// with a 500. Hash userId down to a fixed-length fragment so the receipt's
// length never depends on how long the caller's id happens to be.
function shortId(str) {
  return crypto.createHash("sha256").update(String(str)).digest("hex").slice(0, 10);
}

async function createOrder({ plan, userId, examId }) {
  let amount;
  if (plan === "exampass") {
    if (!examId) throw new Error('An examId is required to buy an exam pass.');
    amount = EXAM_PASS_PRICE_INR;
  } else {
    amount = PLAN_AMOUNTS_INR[plan];
    if (!amount) {
      throw new Error(`Unknown plan "${plan}". Expected "pro", "proplus" or "exampass".`);
    }
  }
  const client = getClient();
  const order = await client.orders.create({
    amount,
    currency: "INR",
    receipt: `pep-${shortId(userId)}-${Date.now().toString(36)}`,
    notes: examId ? { userId, plan, examId } : { userId, plan },
  });
  return order;
}

// Expected amount (paise) for a plan - the single source of truth used both
// when creating an order and when confirming that a payment really paid for
// what the order claims.
function expectedAmount(plan) {
  if (plan === "exampass") return EXAM_PASS_PRICE_INR;
  return PLAN_AMOUNTS_INR[plan] || null;
}

// Confirms a checkout with Razorpay itself instead of trusting the browser.
// The browser's signature only proves that (orderId, paymentId) belong
// together; it says nothing about WHICH plan/user the order was for. So we
// fetch the order and payment from Razorpay and take userId/plan/examId from
// the order's server-side notes (written by createOrder), and check that the
// money paid matches the price of that plan.
// Throws an Error with .status (400/402/502) on any mismatch.
async function confirmPayment({ orderId, paymentId, signature }) {
  const fail = (status, msg) => Object.assign(new Error(msg), { status });
  if (!verifyPaymentSignature({ orderId, paymentId, signature })) {
    throw fail(400, "Payment signature verification failed");
  }
  const client = getClient();
  let order, payment;
  try {
    [order, payment] = await Promise.all([client.orders.fetch(orderId), client.payments.fetch(paymentId)]);
  } catch (e) {
    throw fail(502, "Could not confirm the payment with Razorpay - please contact support with your payment id.");
  }
  if (payment.order_id !== orderId) throw fail(400, "Payment does not belong to this order");
  if (payment.status !== "captured" && payment.status !== "authorized") {
    throw fail(402, `Payment is not complete (status: ${payment.status})`);
  }
  const { userId, plan, examId } = order.notes || {};
  const want = expectedAmount(plan);
  if (!userId || !plan || !want) throw fail(400, "Order is missing plan details");
  if (plan === "exampass" && !examId) throw fail(400, "Order is missing the exam for this pass");
  if (order.amount !== want || payment.amount !== want || payment.currency !== "INR") {
    throw fail(400, "Payment amount does not match the plan price");
  }
  return { userId, plan, examId: examId || null, orderId, paymentId, amount: payment.amount };
}

function verifyPaymentSignature({ orderId, paymentId, signature }) {
  const { RAZORPAY_KEY_SECRET } = process.env;
  const expected = crypto
    .createHmac("sha256", RAZORPAY_KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest("hex");
  return safeEqual(expected, signature);
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
  return safeEqual(expected, signatureHeader);
}

module.exports = { PLAN_AMOUNTS_INR, EXAM_PASS_PRICE_INR, expectedAmount, createOrder, confirmPayment, verifyPaymentSignature, verifyWebhookSignature };
