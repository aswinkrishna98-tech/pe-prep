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

module.exports = { PLAN_AMOUNTS_INR, EXAM_PASS_PRICE_INR, createOrder, verifyPaymentSignature, verifyWebhookSignature };
