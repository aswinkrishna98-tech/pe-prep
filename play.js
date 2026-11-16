// Google Play Billing: server-side verification of one-time in-app purchases
// made inside the Android app (a Trusted Web Activity). The app only ever
// sends us a purchase token; what it unlocks is decided here, from Google's
// own record of that token, never from anything the client claims.
//
// Products (create these as one-time "in-app products" in Play Console):
//   pro              -> plan "pro"
//   proplus          -> plan "proplus"
//   pass_<examId>    -> single-exam pass, hyphens written as underscores: pass_ugc_net, pass_kvs_pgt, pass_sainik_school
//
// Environment:
//   PLAY_PACKAGE_NAME                  Android package name, e.g. com.physicaledmastery.app
//   GOOGLE_PLAY_SERVICE_ACCOUNT_JSON   service-account key JSON (as a string) that has been
//                                      granted access to the app in Play Console
const { GoogleAuth } = require("google-auth-library");

const PLAY_PACKAGE_NAME = () => process.env.PLAY_PACKAGE_NAME || "";

// Map a Play product id to what it grants. Returns null for unknown ids.
function productToGrant(productId, validExamIds) {
  if (productId === "pro") return { plan: "pro" };
  if (productId === "proplus") return { plan: "proplus" };
  // Play product ids cannot contain hyphens, so exam ids use underscores here (pass_ugc_net -> ugc-net).
  const m = /^pass_([a-z0-9_]+)$/.exec(productId || "");
  const examId = m ? m[1].replace(/_/g, "-") : null;
  if (examId && (!validExamIds || validExamIds.includes(examId))) return { plan: "exampass", examId };
  return null;
}

let authClient = null;
function getAuth() {
  if (authClient) return authClient;
  const raw = process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON;
  if (!raw) throw Object.assign(new Error("Play billing is not configured"), { status: 503 });
  authClient = new GoogleAuth({
    credentials: JSON.parse(raw),
    scopes: ["https://www.googleapis.com/auth/androidpublisher"],
  });
  return authClient;
}

const BASE = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications";

// Looks the token up with Google. Returns { ok, purchase } or throws with a status.
async function fetchPurchase(productId, token, fetchImpl = fetch) {
  const pkg = PLAY_PACKAGE_NAME();
  if (!pkg) throw Object.assign(new Error("Play billing is not configured"), { status: 503 });
  const client = await getAuth().getClient();
  const { token: accessToken } = await client.getAccessToken();
  const url = `${BASE}/${encodeURIComponent(pkg)}/purchases/products/${encodeURIComponent(productId)}/tokens/${encodeURIComponent(token)}`;
  const r = await fetchImpl(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (r.status === 404 || r.status === 410 || r.status === 400)
    throw Object.assign(new Error("Purchase not found"), { status: 402 });
  if (!r.ok) throw Object.assign(new Error("Could not verify purchase with Google Play"), { status: 502 });
  return { purchase: await r.json(), accessToken };
}

// Play refunds unacknowledged purchases after 3 days, so acknowledge once we have granted access.
async function acknowledge(productId, token, accessToken, fetchImpl = fetch) {
  const pkg = PLAY_PACKAGE_NAME();
  const url = `${BASE}/${encodeURIComponent(pkg)}/purchases/products/${encodeURIComponent(productId)}/tokens/${encodeURIComponent(token)}:acknowledge`;
  const r = await fetchImpl(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: "{}",
  });
  if (!r.ok) console.warn("[play] acknowledge failed:", r.status);
}

// purchaseState: 0 purchased, 1 canceled, 2 pending
function isPaid(purchase) {
  return purchase && purchase.purchaseState === 0;
}

module.exports = { productToGrant, fetchPurchase, acknowledge, isPaid };
