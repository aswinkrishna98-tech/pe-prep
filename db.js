const fs = require("fs");
const path = require("path");

const DB_PATH = path.join(__dirname, "data", "users.json");

function loadRaw() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch (e) {
    return {};
  }
}

function saveRaw(data) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

function getUser(userId) {
  const data = loadRaw();
  return data[userId] || { plan: "free", updatedAt: null, orders: [] };
}

function setPlan(userId, plan) {
  const data = loadRaw();
  const existing = data[userId] || { plan: "free", orders: [] };
  data[userId] = { ...existing, plan, updatedAt: new Date().toISOString() };
  saveRaw(data);
  return data[userId];
}

function recordOrder(userId, order) {
  const data = loadRaw();
  const existing = data[userId] || { plan: "free", orders: [] };
  existing.orders = existing.orders || [];
  existing.orders.push({ ...order, at: new Date().toISOString() });
  data[userId] = existing;
  saveRaw(data);
}

module.exports = { getUser, setPlan, recordOrder };

