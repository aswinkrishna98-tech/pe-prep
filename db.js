const { Pool } = require("pg");
const crypto = require("crypto");

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.warn(
    "DATABASE_URL is not set - db.js will fail on first use. " +
      "Add a Postgres instance in Render and link its connection string as DATABASE_URL."
  );
}

const pool = new Pool({
  connectionString,
  ssl: connectionString && !connectionString.includes(".internal") ? { rejectUnauthorized: false } : false,
});

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      plan TEXT NOT NULL DEFAULT 'free',
      updated_at TIMESTAMPTZ
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      order_id TEXT,
      payment_id TEXT,
      amount INTEGER,
      source TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // Real login accounts (email+password and/or Google). A signed-in user's
  // `id` here doubles as their `user_id` in the `users`/`orders` tables
  // above, so their plan/payment history keeps working unchanged once they
  // sign in — no separate identity to reconcile.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      google_sub TEXT UNIQUE,
      name TEXT NOT NULL DEFAULT 'Aspirant',
      xp INTEGER NOT NULL DEFAULT 0,
      streak INTEGER NOT NULL DEFAULT 0,
      last_active_date TEXT,
      questions_solved INTEGER NOT NULL DEFAULT 0,
      accuracy_sum INTEGER NOT NULL DEFAULT 0,
      mock_tests_taken INTEGER NOT NULL DEFAULT 0,
      revealed_ids JSONB NOT NULL DEFAULT '{}'::jsonb,
      preferred_exam TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // Added after the initial release — ADD COLUMN IF NOT EXISTS so this is
  // safe to re-run against a database that already has the accounts table.
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS preferred_exam TEXT;`);
}

async function getUser(userId) {
  const { rows } = await pool.query("SELECT user_id, plan, updated_at FROM users WHERE user_id = $1", [userId]);
  if (rows.length === 0) {
    return { plan: "free", updatedAt: null, orders: [] };
  }
  const ordersRes = await pool.query(
    "SELECT order_id AS \"orderId\", payment_id AS \"paymentId\", amount, source, created_at AS \"at\" FROM orders WHERE user_id = $1 ORDER BY created_at ASC",
    [userId]
  );
  return { plan: rows[0].plan, updatedAt: rows[0].updated_at, orders: ordersRes.rows };
}

async function setPlan(userId, plan) {
  const { rows } = await pool.query(
    `INSERT INTO users (user_id, plan, updated_at) VALUES ($1, $2, now())
     ON CONFLICT (user_id) DO UPDATE SET plan = EXCLUDED.plan, updated_at = now()
     RETURNING plan, updated_at`,
    [userId, plan]
  );
  return { plan: rows[0].plan, updatedAt: rows[0].updated_at };
}

async function recordOrder(userId, order) {
  await pool.query(
    `INSERT INTO users (user_id, plan) VALUES ($1, 'free') ON CONFLICT (user_id) DO NOTHING`,
    [userId]
  );
  await pool.query(
    `INSERT INTO orders (user_id, order_id, payment_id, amount, source) VALUES ($1, $2, $3, $4, $5)`,
    [userId, order.orderId || null, order.paymentId || null, order.amount || null, order.source || null]
  );
}

// ---------------------------------------------------------------------------
// Accounts (real login)
// ---------------------------------------------------------------------------
const ACCOUNT_FIELDS = `id, email, name, xp, streak, last_active_date AS "lastActiveDate", ` +
  `questions_solved AS "questionsSolved", accuracy_sum AS "accuracySum", mock_tests_taken AS "mockTestsTaken", ` +
  `revealed_ids AS "revealedIds", preferred_exam AS "preferredExam", created_at AS "createdAt"`;

async function createAccount({ email, passwordHash, googleSub, name, preferredExam }) {
  const id = crypto.randomUUID();
  const { rows } = await pool.query(
    `INSERT INTO accounts (id, email, password_hash, google_sub, name, preferred_exam)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING ${ACCOUNT_FIELDS}`,
    [id, email, passwordHash || null, googleSub || null, (name || "Aspirant").slice(0, 40), preferredExam || null]
  );
  return rows[0];
}

async function getAccountByEmail(email) {
  const { rows } = await pool.query(
    `SELECT ${ACCOUNT_FIELDS}, password_hash AS "passwordHash" FROM accounts WHERE email = $1`,
    [email]
  );
  return rows[0] || null;
}

async function getAccountByGoogleSub(googleSub) {
  const { rows } = await pool.query(`SELECT ${ACCOUNT_FIELDS} FROM accounts WHERE google_sub = $1`, [googleSub]);
  return rows[0] || null;
}

async function getAccountById(id) {
  const { rows } = await pool.query(`SELECT ${ACCOUNT_FIELDS} FROM accounts WHERE id = $1`, [id]);
  return rows[0] || null;
}

async function linkGoogleSub(accountId, googleSub) {
  await pool.query(`UPDATE accounts SET google_sub = $2, updated_at = now() WHERE id = $1`, [accountId, googleSub]);
}

const PROFILE_FIELD_COLUMNS = {
  name: "name",
  xp: "xp",
  streak: "streak",
  lastActiveDate: "last_active_date",
  questionsSolved: "questions_solved",
  accuracySum: "accuracy_sum",
  mockTestsTaken: "mock_tests_taken",
  revealedIds: "revealed_ids",
  preferredExam: "preferred_exam",
};

async function updateAccountProfile(accountId, fields) {
  const sets = [];
  const values = [accountId];
  let i = 2;
  for (const [key, column] of Object.entries(PROFILE_FIELD_COLUMNS)) {
    if (fields[key] === undefined) continue;
    sets.push(`${column} = $${i}`);
    values.push(key === "revealedIds" ? JSON.stringify(fields[key]) : (key === "name" ? String(fields[key]).slice(0, 40) : fields[key]));
    i++;
  }
  if (sets.length === 0) return getAccountById(accountId);
  sets.push("updated_at = now()");
  const { rows } = await pool.query(
    `UPDATE accounts SET ${sets.join(", ")} WHERE id = $1 RETURNING ${ACCOUNT_FIELDS}`,
    values
  );
  return rows[0];
}

module.exports = {
  pool, ensureSchema, getUser, setPlan, recordOrder,
  createAccount, getAccountByEmail, getAccountByGoogleSub, getAccountById, linkGoogleSub, updateAccountProfile,
};
