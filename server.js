const crypto = require("crypto");
const express = require("express");
const nodemailer = require("nodemailer");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const port = process.env.PORT || 3000;
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, "data.sqlite");
const masterEmail = "sachinn.agarrwal@gmail.com";
const sessionCookie = "agrimill_session";
const sessionLifetimeMs = 12 * 60 * 60 * 1000;
const otpLifetimeMs = 10 * 60 * 1000;
const departmentModules = {
  admin: ["dashboard", "dailyReview", "editLog", "production", "inventory", "inventoryMovement", "inventoryPurchases", "stores", "storesPurchases", "stockMovement", "purchases", "purchaseOrders", "sales", "salesOrders", "brokerage", "accounting", "employees", "userManagement"],
  production: ["dashboard", "production", "inventory", "inventoryMovement"],
  inventory: ["dashboard", "inventory", "inventoryPurchases", "inventoryMovement"],
  stores: ["dashboard", "stores", "storesPurchases", "stockMovement"],
  purchase: ["dashboard", "purchases", "purchaseOrders"],
  sales: ["dashboard", "sales", "salesOrders", "brokerage", "inventory"],
  accounts: ["dashboard", "accounting", "purchases", "sales", "brokerage"],
  hr: ["dashboard", "employees"]
};
const departmentLabels = {
  admin: "Administrator",
  production: "Production",
  inventory: "Inventory",
  stores: "Stores",
  purchase: "Purchase",
  sales: "Sales",
  accounts: "Accounts",
  hr: "Human Resources"
};
const sharedStorageModules = {
  "inventory-items": ["inventory", "stores", "sales"],
  "stockMovement": ["stockMovement", "inventoryMovement", "sales"],
  "inventory-purchases": ["inventoryPurchases", "storesPurchases"],
  "paddy-purchase-migrations": ["purchases", "inventoryPurchases"]
};
const readOnlyStorageModules = {
  purchases: ["production"]
};
const requestLimits = new Map();
const db = new sqlite3.Database(dbPath);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) reject(error);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => error ? reject(error) : resolve(row));
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows));
  });
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function checkRateLimit(key, limit, windowMs) {
  const now = Date.now();
  const current = requestLimits.get(key);
  if (!current || now - current.startedAt >= windowMs) {
    requestLimits.set(key, { startedAt: now, count: 1 });
    return true;
  }
  if (current.count >= limit) return false;
  current.count += 1;
  return true;
}

function requireRateLimit(key, limit, windowMs) {
  if (!checkRateLimit(key, limit, windowMs)) {
    throw new HttpError(429, "Too many attempts. Please wait before trying again.");
  }
}

function hashOtp(code, salt) {
  return crypto.createHmac("sha256", process.env.GMAIL_APP_PASSWORD)
    .update(`${salt}:${code}`).digest();
}

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) reject(error);
      else resolve({ salt, hash: derivedKey.toString("hex") });
    });
  });
}

function verifyPassword(password, salt, hash) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) reject(error);
      else {
        const expected = Buffer.from(hash, "hex");
        resolve(expected.length === derivedKey.length && crypto.timingSafeEqual(expected, derivedKey));
      }
    });
  });
}

function validatePassword(password) {
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    throw new HttpError(400, "Choose a password between 12 and 128 characters.");
  }
}

function getTransport() {
  const gmailUser = normalizeEmail(process.env.GMAIL_USER);
  const appPassword = process.env.GMAIL_APP_PASSWORD;
  if (gmailUser !== masterEmail || !appPassword) {
    throw new HttpError(503, "Gmail OTP delivery is not configured. Set GMAIL_USER and GMAIL_APP_PASSWORD in Render.");
  }

  return nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: { user: gmailUser, pass: appPassword.replace(/\s/g, "") }
  });
}

async function sendOtp(email, purpose, req, accountMessage = "") {
  requireRateLimit(`otp-ip:${req.ip}`, 10, 10 * 60 * 1000);
  const mailer = getTransport();
  const now = Date.now();
  const existing = await get("SELECT sent_at FROM auth_otps WHERE email = ? AND purpose = ?", [email, purpose]);
  if (existing && now - existing.sent_at < 60 * 1000) {
    throw new HttpError(429, "A code was sent recently. Please wait one minute before requesting another.");
  }

  const code = String(crypto.randomInt(100000, 1000000));
  const salt = crypto.randomBytes(16).toString("hex");
  await run(
    `INSERT INTO auth_otps (email, purpose, code_hash, salt, expires_at, attempts, sent_at)
     VALUES (?, ?, ?, ?, ?, 0, ?)
     ON CONFLICT(email, purpose) DO UPDATE SET code_hash = excluded.code_hash,
       salt = excluded.salt, expires_at = excluded.expires_at, attempts = 0, sent_at = excluded.sent_at`,
    [email, purpose, hashOtp(code, salt).toString("hex"), salt, now + otpLifetimeMs, now]
  );

  try {
    await mailer.sendMail({
      from: normalizeEmail(process.env.GMAIL_USER),
      to: email,
      subject: "Your AgriMill ERP verification code",
      text: `Your AgriMill ERP verification code is ${code}. ${accountMessage} It expires in 10 minutes. If you did not request this code, you can ignore this message.`
    });
  } catch (error) {
    await run("DELETE FROM auth_otps WHERE email = ? AND purpose = ?", [email, purpose]);
    console.error("Could not send an AgriMill verification email.", error);
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "Could not send the verification email. Check the Gmail settings in Render and try again.");
  }
}

async function consumeOtp(email, purpose, code) {
  const challenge = await get(
    "SELECT code_hash, salt, expires_at, attempts FROM auth_otps WHERE email = ? AND purpose = ?",
    [email, purpose]
  );
  if (!challenge || challenge.expires_at < Date.now() || challenge.attempts >= 5) {
    await run("DELETE FROM auth_otps WHERE email = ? AND purpose = ?", [email, purpose]);
    return false;
  }

  const candidate = typeof code === "string" && /^\d{6}$/.test(code)
    ? hashOtp(code, challenge.salt)
    : Buffer.alloc(32);
  const expected = Buffer.from(challenge.code_hash, "hex");
  if (candidate.length !== expected.length || !crypto.timingSafeEqual(candidate, expected)) {
    await run(
      "UPDATE auth_otps SET attempts = attempts + 1 WHERE email = ? AND purpose = ? AND attempts < 5",
      [email, purpose]
    );
    return false;
  }

  const consumed = await run(
    "DELETE FROM auth_otps WHERE email = ? AND purpose = ? AND code_hash = ? AND expires_at >= ? AND attempts < 5",
    [email, purpose, challenge.code_hash, Date.now()]
  );
  return consumed.changes === 1;
}

function publicUser(user) {
  return {
    accountId: user.user_id,
    email: user.email,
    name: user.name,
    departmentId: user.department_id,
    role: departmentLabels[user.department_id],
    isMaster: Boolean(user.is_master)
  };
}

function cookieValue(req, name) {
  const cookie = (req.headers.cookie || "").split(";").map(part => part.trim())
    .find(part => part.startsWith(`${name}=`));
  return cookie ? decodeURIComponent(cookie.slice(name.length + 1)) : "";
}

function writeSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${sessionCookie}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${sessionLifetimeMs / 1000}${secure}`);
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${sessionCookie}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}

async function createSession(res, user) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + sessionLifetimeMs;
  await run("DELETE FROM auth_sessions WHERE expires_at <= ?", [Date.now()]);
  await run("INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)", [
    crypto.createHash("sha256").update(token).digest("hex"),
    user.user_id,
    expiresAt
  ]);
  writeSessionCookie(res, token);
  return publicUser(user);
}

const requireUser = asyncRoute(async (req, res, next) => {
  const token = cookieValue(req, sessionCookie);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    throw new HttpError(401, "Please sign in to continue.");
  }

  const user = await get(
    `SELECT u.user_id, u.email, u.name, u.department_id, u.is_master
     FROM auth_sessions s JOIN auth_users u ON u.user_id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_active = 1`,
    [crypto.createHash("sha256").update(token).digest("hex"), Date.now()]
  );
  if (!user) {
    clearSessionCookie(res);
    throw new HttpError(401, "Your session has expired. Please sign in again.");
  }

  req.user = user;
  next();
});

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.is_master) {
    res.status(403).json({ error: "Administrator access is required." });
    return;
  }
  next();
}

function storageModules(key) {
  if (!key.startsWith("agrimill-") || key === "agrimill-user") return [];
  const moduleId = key.slice("agrimill-".length);
  if (sharedStorageModules[moduleId]) return sharedStorageModules[moduleId];
  if (readOnlyStorageModules[moduleId]) return [moduleId, ...readOnlyStorageModules[moduleId]];
  if (moduleId === "dryerBatches" || moduleId === "millingRuns") return ["production"];
  return [moduleId];
}

function canReadStorageKey(user, key) {
  return Boolean(user.is_master)
    || storageModules(key).some(moduleId => departmentModules[user.department_id]?.includes(moduleId));
}

function canWriteStorageKey(user, key) {
  if (user.is_master) return true;
  return !(key === "agrimill-purchases" && user.department_id === "production")
    && canReadStorageKey(user, key);
}

function getAccessibleDomains(user) {
  if (user.is_master) return ["inventory", "stores"];
  const modules = departmentModules[user.department_id] || [];
  return [
    ...(modules.includes("inventory") ? ["inventory"] : []),
    ...(modules.includes("stores") ? ["stores"] : [])
  ];
}

function productDomain(item) {
  const category = String(item?.category || "").trim().toLowerCase();
  if (["packaging", "spare parts", "consumables"].includes(category)) return "stores";
  if (["raw material", "finished goods", "by-product"].includes(category)
    || ["paddy", "rice", "by-product", "byproduct"].includes(category)
    || /\b(paddy|rice|byproducts?)\b/i.test(item?.name || "")) return "inventory";
  return "stores";
}

function parseStorageArray(value, status = 500) {
  let records;
  try {
    records = JSON.parse(value);
  } catch (error) {
    if (status === 400) throw new HttpError(400, "Submitted department data is not a valid record list.");
    console.error("Could not parse stored department data.", error);
    throw new HttpError(500, "Stored department data is not a valid record list.");
  }
  if (!Array.isArray(records)) {
    const message = status === 400
      ? "Submitted department data is not a valid record list."
      : "Stored department data is not a valid record list.";
    throw new HttpError(status, message);
  }
  return records;
}

async function getAllInventoryItems() {
  const row = await get("SELECT value FROM storage WHERE key = 'agrimill-inventory-items'");
  return row ? parseStorageArray(row.value) : [];
}

function getStorageRecordDomain(key, record, inventoryItems) {
  if (key === "agrimill-inventory-items") return productDomain(record);
  if (key === "agrimill-stockMovement") {
    const item = inventoryItems.find(candidate => candidate.sku === record[3]);
    return productDomain(item || { name: record[4] });
  }
  if (key === "agrimill-inventory-purchases") {
    const item = inventoryItems.find(candidate => candidate.sku === record[3]);
    return productDomain(item || { name: record[4], category: record[5] });
  }
  return null;
}

async function filterStorageValue(user, key, value) {
  if (user.department_id === "production" && key === "agrimill-purchases") {
    return JSON.stringify(parseStorageArray(value).map(record => {
      const visibleRecord = [...record];
      visibleRecord[1] = "—";
      visibleRecord[3] = "—";
      return visibleRecord;
    }));
  }
  if (user.is_master || !["agrimill-inventory-items", "agrimill-stockMovement", "agrimill-inventory-purchases"].includes(key)) {
    return value;
  }
  const domains = getAccessibleDomains(user);
  const items = key === "agrimill-inventory-items" ? [] : await getAllInventoryItems();
  const records = parseStorageArray(value);
  const visible = [];
  for (const record of records) {
    if (domains.includes(getStorageRecordDomain(key, record, items))) visible.push(record);
  }
  return JSON.stringify(visible);
}

async function mergeStorageValue(user, key, value) {
  if (user.is_master || !["agrimill-inventory-items", "agrimill-stockMovement", "agrimill-inventory-purchases"].includes(key)) {
    return value;
  }
  const domains = getAccessibleDomains(user);
  const currentRow = await get("SELECT value FROM storage WHERE key = ?", [key]);
  const existing = currentRow ? parseStorageArray(currentRow.value) : [];
  const incoming = parseStorageArray(value, 400);
  const items = key === "agrimill-inventory-items" ? [] : await getAllInventoryItems();
  const merged = [];
  for (const record of existing) {
    if (!domains.includes(getStorageRecordDomain(key, record, items))) merged.push(record);
  }
  for (const record of incoming) {
    if (domains.includes(getStorageRecordDomain(key, record, items))) merged.push(record);
  }
  return JSON.stringify(merged);
}

async function deleteStorageKey(user, key) {
  if (user.is_master || !["agrimill-inventory-items", "agrimill-stockMovement", "agrimill-inventory-purchases"].includes(key)) {
    await run("DELETE FROM storage WHERE key = ?", [key]);
    return;
  }
  const row = await get("SELECT value FROM storage WHERE key = ?", [key]);
  if (!row) return;
  const domains = getAccessibleDomains(user);
  const items = key === "agrimill-inventory-items" ? [] : await getAllInventoryItems();
  const remaining = [];
  for (const record of parseStorageArray(row.value)) {
    if (!domains.includes(getStorageRecordDomain(key, record, items))) remaining.push(record);
  }
  if (remaining.length) {
    await run("UPDATE storage SET value = ? WHERE key = ?", [JSON.stringify(remaining), key]);
  } else {
    await run("DELETE FROM storage WHERE key = ?", [key]);
  }
}

async function initializeDatabase() {
  await run("CREATE TABLE IF NOT EXISTS storage (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
  await run(`CREATE TABLE IF NOT EXISTS auth_users (
    user_id TEXT PRIMARY KEY COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    department_id TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 0,
    is_master INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS auth_otps (
    email TEXT NOT NULL COLLATE NOCASE,
    purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    sent_at INTEGER NOT NULL,
    PRIMARY KEY (email, purpose)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
  )`);
  await run("CREATE INDEX IF NOT EXISTS auth_sessions_user_id_idx ON auth_sessions(user_id)");
  await run("CREATE UNIQUE INDEX IF NOT EXISTS auth_users_single_master_idx ON auth_users(is_master) WHERE is_master = 1");
  await run("DELETE FROM storage WHERE key = 'agrimill-user'");
  await run("DELETE FROM auth_sessions WHERE expires_at <= ?", [Date.now()]);
}

app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use("/api", (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.get("/app.js", (_req, res) => res.sendFile(path.join(__dirname, "app.js")));
app.get("/styles.css", (_req, res) => res.sendFile(path.join(__dirname, "styles.css")));
app.get("/api/health", (_req, res) => res.json({ ok: true, service: "agrimill-erp-backend" }));

app.get("/api/auth/session", asyncRoute(async (_req, res) => {
  const master = await get("SELECT 1 FROM auth_users WHERE is_master = 1");
  const token = cookieValue(_req, sessionCookie);
  let user = null;
  if (token && /^[a-f0-9]{64}$/.test(token)) {
    user = await get(
      `SELECT u.user_id, u.email, u.name, u.department_id, u.is_master
       FROM auth_sessions s JOIN auth_users u ON u.user_id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_active = 1`,
      [crypto.createHash("sha256").update(token).digest("hex"), Date.now()]
    );
    if (!user) clearSessionCookie(res);
  }
  res.json({ initialized: Boolean(master), user: user ? publicUser(user) : null });
}));

app.post("/api/auth/bootstrap/request-otp", asyncRoute(async (req, res) => {
  requireRateLimit(`bootstrap-ip:${req.ip}`, 5, 10 * 60 * 1000);
  const master = await get("SELECT 1 FROM auth_users WHERE is_master = 1");
  if (master) throw new HttpError(409, "The administrator account has already been created.");
  await sendOtp(masterEmail, "bootstrap", req);
  res.json({ ok: true, message: `A verification code was sent to ${masterEmail}.` });
}));

app.post("/api/auth/bootstrap/complete", asyncRoute(async (req, res) => {
  const master = await get("SELECT 1 FROM auth_users WHERE is_master = 1");
  if (master) throw new HttpError(409, "The administrator account has already been created.");
  const { code, password } = req.body || {};
  validatePassword(password);
  if (!await consumeOtp(masterEmail, "bootstrap", code)) {
    throw new HttpError(400, "The verification code is invalid or expired.");
  }
  const credentials = await hashPassword(password);
  try {
    await run(
      `INSERT INTO auth_users
        (user_id, email, name, department_id, password_salt, password_hash, email_verified, is_active, is_master, created_at)
       VALUES (?, ?, ?, 'admin', ?, ?, 1, 1, 1, ?)`,
      [masterEmail, masterEmail, "Sachin Agarwal", credentials.salt, credentials.hash, Date.now()]
    );
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT") throw new HttpError(409, "The administrator account has already been created.");
    throw error;
  }
  const user = await get("SELECT user_id, email, name, department_id, is_master FROM auth_users WHERE is_master = 1");
  res.json({ ok: true, user: await createSession(res, user) });
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const userId = typeof req.body?.userId === "string" ? req.body.userId.trim() : "";
  const password = req.body?.password;
  if (!userId || userId.length > 64 || typeof password !== "string" || password.length > 128) {
    throw new HttpError(400, "Enter a valid user ID and password.");
  }
  requireRateLimit(`login-ip:${req.ip}`, 60, 10 * 60 * 1000);
  requireRateLimit(`login:${req.ip}:${userId.toLowerCase()}`, 10, 10 * 60 * 1000);
  const user = await get(
    "SELECT user_id, email, name, department_id, password_salt, password_hash, is_master FROM auth_users WHERE user_id = ? AND is_active = 1 AND email_verified = 1",
    [userId]
  );
  if (!user || typeof password !== "string" || !await verifyPassword(password, user.password_salt, user.password_hash)) {
    throw new HttpError(401, "User ID or password is incorrect.");
  }
  res.json({ ok: true, user: await createSession(res, user) });
}));

app.post("/api/auth/logout", asyncRoute(async (req, res) => {
  const token = cookieValue(req, sessionCookie);
  if (/^[a-f0-9]{64}$/.test(token)) {
    await run("DELETE FROM auth_sessions WHERE token_hash = ?", [
      crypto.createHash("sha256").update(token).digest("hex")
    ]);
  }
  clearSessionCookie(res);
  res.json({ ok: true });
}));

app.post("/api/auth/invite/complete", asyncRoute(async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const { code, password } = req.body || {};
  validatePassword(password);
  const user = await get(
    "SELECT user_id FROM auth_users WHERE email = ? AND is_active = 0 AND is_master = 0",
    [email]
  );
  if (!user || !await consumeOtp(email, "invite", code)) {
    throw new HttpError(400, "The invitation code is invalid or expired.");
  }
  const credentials = await hashPassword(password);
  await run(
    "UPDATE auth_users SET password_salt = ?, password_hash = ?, email_verified = 1, is_active = 1 WHERE user_id = ?",
    [credentials.salt, credentials.hash, user.user_id]
  );
  res.json({ ok: true, message: "Account activated. Sign in with your assigned user ID and new password." });
}));

app.post("/api/auth/password/request-otp", asyncRoute(async (req, res) => {
  requireRateLimit(`reset-ip:${req.ip}`, 10, 10 * 60 * 1000);
  const email = normalizeEmail(req.body?.email);
  if (!email) throw new HttpError(400, "Enter the email address on your account.");
  const user = await get(
    "SELECT email FROM auth_users WHERE email = ? AND is_active = 1 AND email_verified = 1",
    [email]
  );
  if (user) await sendOtp(email, "password-reset", req);
  res.json({ ok: true, message: "If an active account uses that email, a verification code has been sent." });
}));

app.post("/api/auth/password/complete", asyncRoute(async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const { code, password } = req.body || {};
  validatePassword(password);
  const user = await get(
    "SELECT user_id FROM auth_users WHERE email = ? AND is_active = 1 AND email_verified = 1",
    [email]
  );
  if (!user || !await consumeOtp(email, "password-reset", code)) {
    throw new HttpError(400, "The verification code is invalid or expired.");
  }
  const credentials = await hashPassword(password);
  await run("UPDATE auth_users SET password_salt = ?, password_hash = ? WHERE user_id = ?", [
    credentials.salt, credentials.hash, user.user_id
  ]);
  await run("DELETE FROM auth_sessions WHERE user_id = ?", [user.user_id]);
  res.json({ ok: true, message: "Password updated. Sign in with your new password." });
}));

app.get("/api/admin/users", requireUser, requireAdmin, asyncRoute(async (_req, res) => {
  const users = await all(
    `SELECT user_id AS userId, email, name, department_id AS departmentId, is_active AS isActive,
      email_verified AS emailVerified, created_at AS createdAt
     FROM auth_users WHERE is_master = 0 ORDER BY created_at DESC`
  );
  res.json({ users: users.map(user => ({
    ...user,
    isActive: Boolean(user.isActive),
    emailVerified: Boolean(user.emailVerified),
    role: departmentLabels[user.departmentId]
  })) });
}));

app.post("/api/admin/users", requireUser, requireAdmin, asyncRoute(async (req, res) => {
  const userId = typeof req.body?.userId === "string" ? req.body.userId.trim() : "";
  const email = normalizeEmail(req.body?.email);
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  const departmentId = req.body?.departmentId;
  if (!/^[a-zA-Z0-9._-]{3,48}$/.test(userId)) {
    throw new HttpError(400, "User ID must be 3–48 characters and use letters, numbers, dots, underscores, or hyphens.");
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    throw new HttpError(400, "Enter a valid staff email address.");
  }
  if (!name || name.length > 100) throw new HttpError(400, "Enter a name of up to 100 characters.");
  if (!Object.hasOwn(departmentModules, departmentId) || departmentId === "admin") {
    throw new HttpError(400, "Choose a valid non-administrator department.");
  }
  try {
    await run(
      `INSERT INTO auth_users (user_id, email, name, department_id, password_salt, password_hash, created_at)
       VALUES (?, ?, ?, ?, '', '', ?)`,
      [userId, email, name, departmentId, Date.now()]
    );
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT") throw new HttpError(409, "That user ID or email is already in use.");
    throw error;
  }
  try {
    await sendOtp(email, "invite", req, `Your assigned user ID is ${userId}.`);
  } catch (error) {
    await run("DELETE FROM auth_users WHERE user_id = ? AND is_active = 0", [userId]);
    throw error;
  }
  res.status(201).json({ ok: true, message: `Invitation sent to ${email}.` });
}));

app.post("/api/admin/users/:userId/resend-invite", requireUser, requireAdmin, asyncRoute(async (req, res) => {
  const user = await get("SELECT user_id, email FROM auth_users WHERE user_id = ? AND is_master = 0 AND is_active = 0", [req.params.userId]);
  if (!user) throw new HttpError(404, "Pending invitation not found.");
  await sendOtp(user.email, "invite", req, `Your assigned user ID is ${user.user_id}.`);
  res.json({ ok: true, message: `A new invitation code was sent to ${user.email}.` });
}));

app.post("/api/admin/users/:userId/reset-otp", requireUser, requireAdmin, asyncRoute(async (req, res) => {
  const user = await get("SELECT email FROM auth_users WHERE user_id = ? AND is_master = 0 AND is_active = 1", [req.params.userId]);
  if (!user) throw new HttpError(404, "Active staff account not found.");
  await sendOtp(user.email, "password-reset", req);
  res.json({ ok: true, message: `A password reset code was sent to ${user.email}.` });
}));

app.patch("/api/admin/users/:userId/status", requireUser, requireAdmin, asyncRoute(async (req, res) => {
  const active = req.body?.active;
  if (typeof active !== "boolean") throw new HttpError(400, "An active status is required.");
  const user = await get("SELECT user_id, email_verified FROM auth_users WHERE user_id = ? AND is_master = 0", [req.params.userId]);
  if (!user) throw new HttpError(404, "Staff account not found.");
  if (active && !user.email_verified) throw new HttpError(409, "Staff must verify their invitation email before activation.");
  await run("UPDATE auth_users SET is_active = ? WHERE user_id = ?", [active ? 1 : 0, user.user_id]);
  if (!active) await run("DELETE FROM auth_sessions WHERE user_id = ?", [user.user_id]);
  res.json({ ok: true });
}));

app.delete("/api/admin/users/:userId", requireUser, requireAdmin, asyncRoute(async (req, res) => {
  const user = await get("SELECT user_id FROM auth_users WHERE user_id = ? AND is_master = 0", [req.params.userId]);
  if (!user) throw new HttpError(404, "Staff account not found.");
  await run("DELETE FROM auth_sessions WHERE user_id = ?", [user.user_id]);
  await run("DELETE FROM auth_otps WHERE email = (SELECT email FROM auth_users WHERE user_id = ?)", [user.user_id]);
  await run("DELETE FROM auth_users WHERE user_id = ?", [user.user_id]);
  res.json({ ok: true });
}));

app.get("/api/storage", requireUser, asyncRoute(async (req, res) => {
  const key = typeof req.query.key === "string" ? req.query.key : null;
  if (key) {
    if (!canReadStorageKey(req.user, key)) throw new HttpError(403, "You do not have access to this department's data.");
    const row = await get("SELECT value FROM storage WHERE key = ?", [key]);
    res.json({ key, value: row ? await filterStorageValue(req.user, key, row.value) : null });
    return;
  }

  const rows = await all("SELECT key, value FROM storage ORDER BY key");
  const payload = {};
  for (const row of rows) {
    if (canReadStorageKey(req.user, row.key)) {
      payload[row.key] = await filterStorageValue(req.user, row.key, row.value);
    }
  }
  res.json(payload);
}));

app.post("/api/storage", requireUser, asyncRoute(async (req, res) => {
  const { key, value } = req.body || {};
  if (typeof key !== "string" || key.trim() === "") throw new HttpError(400, "A non-empty string key is required.");
  if (key.length > 128 || key === "agrimill-user") throw new HttpError(400, "Invalid storage key.");
  if (!canWriteStorageKey(req.user, key)) throw new HttpError(403, "You do not have access to change this department's data.");
  const submitted = typeof value === "string" ? value : JSON.stringify(value);
  const serialized = await mergeStorageValue(req.user, key, submitted);
  await run(
    "INSERT INTO storage (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    [key, serialized]
  );
  res.json({ ok: true, key, value: serialized });
}));

app.delete("/api/storage", requireUser, asyncRoute(async (req, res) => {
  const { key } = req.body || req.query || {};
  if (typeof key === "string" && key.trim() !== "") {
    if (!canWriteStorageKey(req.user, key)) throw new HttpError(403, "You do not have access to change this department's data.");
    await deleteStorageKey(req.user, key);
    res.json({ ok: true, key, removed: true });
    return;
  }
  if (req.user.is_master) {
    await run("DELETE FROM storage");
  } else {
    const rows = await all("SELECT key FROM storage");
    for (const row of rows) {
      if (canWriteStorageKey(req.user, row.key)) await deleteStorageKey(req.user, row.key);
    }
  }
  res.json({ ok: true, cleared: true });
}));

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  res.sendFile(path.join(__dirname, "index.html"), error => {
    if (error) next(error);
  });
});

app.use((error, _req, res, _next) => {
  if (error instanceof HttpError) {
    res.status(error.status).json({ error: error.message });
    return;
  }
  console.error("Request failed.", error);
  res.status(500).json({ error: "An unexpected server error occurred." });
});

initializeDatabase().then(() => {
  app.listen(port, () => {
    console.log(`Backend running on port ${port}`);
  });
}).catch(error => {
  console.error("Could not initialize the database.", error);
  process.exit(1);
});
