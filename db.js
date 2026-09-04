const { Pool } = require("pg");

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

module.exports = { pool, ensureSchema, getUser, setPlan, recordOrder };
