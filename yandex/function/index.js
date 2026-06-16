const crypto = require("crypto");
const { S3Client, GetObjectCommand, PutObjectCommand } = require("@aws-sdk/client-s3");

const BUCKET = process.env.YC_STORAGE_BUCKET;
const PREFIX = (process.env.YC_STORAGE_PREFIX || "brew-planner").replace(/^\/+|\/+$/g, "");
const ENDPOINT = process.env.YC_STORAGE_ENDPOINT || "https://storage.yandexcloud.net";
const REGION = process.env.YC_STORAGE_REGION || "ru-central1";
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS || 60 * 60 * 24 * 14);
const PASSWORD_ITERATIONS = 120000;
const ROLES = new Set(["admin", "manager", "reader"]);

const s3 = new S3Client({
  endpoint: ENDPOINT,
  region: REGION,
  forcePathStyle: true,
  credentials: {
    accessKeyId: process.env.YC_ACCESS_KEY_ID || "",
    secretAccessKey: process.env.YC_SECRET_ACCESS_KEY || ""
  }
});

function key(name) {
  return `${PREFIX}/${name}`;
}

const PLAN_KEY = key("plan.json");
const USERS_KEY = key("users.json");
const LOGS_KEY = key("action-logs.json");
const PRESENCE_KEY = key("presence.json");

function jsonResponse(statusCode, body, headers = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": process.env.CORS_ORIGIN || "*",
      "Access-Control-Allow-Headers": "content-type, authorization, x-requested-with",
      "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "Access-Control-Max-Age": "86400",
      ...headers
    },
    body: JSON.stringify(body)
  };
}

function textResponse(statusCode, body, headers = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Access-Control-Allow-Origin": process.env.CORS_ORIGIN || "*",
      "Access-Control-Allow-Headers": "content-type, authorization, x-requested-with",
      "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "Access-Control-Max-Age": "86400",
      ...headers
    },
    body
  };
}

function parseEvent(event) {
  const headers = Object.fromEntries(
    Object.entries(event.headers || {}).map(([name, value]) => [name.toLowerCase(), value])
  );
  const method = String(event.httpMethod || event.requestContext?.http?.method || "GET").toUpperCase();
  const rawPath = event.path || event.rawPath || "/";
  const path = String(rawPath).replace(/^\/api(?=\/|$)/, "") || "/";
  let body = {};
  if (event.body) {
    const rawBody = event.isBase64Encoded ? Buffer.from(event.body, "base64").toString("utf8") : event.body;
    body = rawBody ? JSON.parse(rawBody) : {};
  }
  return { method, path, headers, body };
}

async function streamToString(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function isMissingObjectError(error) {
  return error?.name === "NoSuchKey" || error?.$metadata?.httpStatusCode === 404;
}

async function readJson(objectKey, fallback) {
  try {
    const result = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: objectKey }));
    return JSON.parse(await streamToString(result.Body));
  } catch (error) {
    if (isMissingObjectError(error)) return fallback;
    throw error;
  }
}

async function writeJson(objectKey, value) {
  await s3.send(new PutObjectCommand({
    Bucket: BUCKET,
    Key: objectKey,
    Body: JSON.stringify(value, null, 2),
    ContentType: "application/json; charset=utf-8"
  }));
}

function assertConfig() {
  const missing = [];
  if (!BUCKET) missing.push("YC_STORAGE_BUCKET");
  if (!process.env.YC_ACCESS_KEY_ID) missing.push("YC_ACCESS_KEY_ID");
  if (!process.env.YC_SECRET_ACCESS_KEY) missing.push("YC_SECRET_ACCESS_KEY");
  if (!JWT_SECRET) missing.push("JWT_SECRET");
  if (!ADMIN_EMAIL) missing.push("ADMIN_EMAIL");
  if (!ADMIN_PASSWORD) missing.push("ADMIN_PASSWORD");
  if (missing.length) {
    throw new Error(`Missing environment variables: ${missing.join(", ")}`);
  }
}

function base64url(input) {
  return Buffer.from(input).toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function fromBase64url(input) {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(input.length / 4) * 4, "=");
  return Buffer.from(padded, "base64").toString("utf8");
}

function signToken(user) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({
    sub: user.id,
    email: user.email,
    role: user.role,
    exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS
  }));
  const signature = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${signature}`;
}

function verifyToken(token) {
  const [header, payload, signature] = String(token || "").split(".");
  if (!header || !payload || !signature) throw new Error("Invalid token");
  const expected = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${payload}`).digest("base64url");
  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(actualBuffer, expectedBuffer)) {
    throw new Error("Invalid token");
  }
  const data = JSON.parse(fromBase64url(payload));
  if (Number(data.exp || 0) < Math.floor(Date.now() / 1000)) throw new Error("Token expired");
  return data;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(String(password), salt, PASSWORD_ITERATIONS, 32, "sha256").toString("hex");
  return `pbkdf2_sha256$${PASSWORD_ITERATIONS}$${salt}$${hash}`;
}

function verifyPassword(password, storedHash) {
  const [algorithm, iterations, salt, hash] = String(storedHash || "").split("$");
  if (algorithm !== "pbkdf2_sha256" || !iterations || !salt || !hash) return false;
  const actual = crypto.pbkdf2Sync(String(password), salt, Number(iterations), 32, "sha256").toString("hex");
  const actualBuffer = Buffer.from(actual, "hex");
  const expectedBuffer = Buffer.from(hash, "hex");
  return actualBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    login: user.email,
    displayName: user.displayName || "",
    role: user.role || "reader",
    createdAt: user.createdAt || ""
  };
}

function createUser({ email, password, displayName = "", role = "reader" }) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail.includes("@")) throw new Error("Email is required");
  if (!String(password || "").trim()) throw new Error("Password is required");
  if (!ROLES.has(role)) throw new Error("Invalid role");
  return {
    id: crypto.randomUUID(),
    email: normalizedEmail,
    displayName: String(displayName || "").trim(),
    role,
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString()
  };
}

async function loadUsers() {
  let users = await readJson(USERS_KEY, null);
  if (Array.isArray(users) && users.length) return users;
  const admin = createUser({
    email: ADMIN_EMAIL,
    password: ADMIN_PASSWORD,
    displayName: process.env.ADMIN_DISPLAY_NAME || "Administrator",
    role: "admin"
  });
  users = [admin];
  await writeJson(USERS_KEY, users);
  return users;
}

async function saveUsers(users) {
  await writeJson(USERS_KEY, users);
}

function extractBearer(headers) {
  const value = headers.authorization || "";
  const match = value.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : "";
}

async function requireUser(req) {
  const token = extractBearer(req.headers);
  if (!token) throw Object.assign(new Error("Unauthorized"), { statusCode: 401 });
  const payload = verifyToken(token);
  const users = await loadUsers();
  const user = users.find((item) => item.id === payload.sub);
  if (!user) throw Object.assign(new Error("Unauthorized"), { statusCode: 401 });
  return { user, users };
}

function requireEditor(user) {
  if (user.role === "admin" || user.role === "manager") return;
  throw Object.assign(new Error("Forbidden"), { statusCode: 403 });
}

function requireAdmin(user) {
  if (user.role === "admin") return;
  throw Object.assign(new Error("Forbidden"), { statusCode: 403 });
}

function emptyPlan() {
  return {
    sites: [],
    tanks: [],
    cycles: [],
    productTemplates: [],
    revision: 0,
    updatedAt: null
  };
}

function normalizePlan(input) {
  const source = input?.plan && typeof input.plan === "object" ? input.plan : input;
  return {
    sites: Array.isArray(source?.sites) ? source.sites : [],
    tanks: Array.isArray(source?.tanks) ? source.tanks : [],
    cycles: Array.isArray(source?.cycles) ? source.cycles : [],
    productTemplates: Array.isArray(source?.productTemplates) ? source.productTemplates : []
  };
}

function pruneLogs(logs) {
  const cutoff = Date.now() - 60 * 24 * 60 * 60 * 1000;
  return (Array.isArray(logs) ? logs : [])
    .filter((log) => Date.parse(log.createdAt || "") >= cutoff)
    .sort((a, b) => String(b.createdAt || "").localeCompare(String(a.createdAt || "")))
    .slice(0, 1000);
}

async function handleLogin(req) {
  const email = normalizeEmail(req.body.email || req.body.login);
  const password = req.body.password || "";
  const users = await loadUsers();
  const user = users.find((item) => item.email === email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return jsonResponse(401, { message: "Invalid login or password" });
  }
  return jsonResponse(200, { user: publicUser(user), token: signToken(user) });
}

async function handleUsers(req, auth) {
  const segments = req.path.split("/").filter(Boolean);
  if (req.method === "GET" && segments.length === 1) {
    return jsonResponse(200, { users: auth.users.map(publicUser).sort((a, b) => a.email.localeCompare(b.email)) });
  }
  requireAdmin(auth.user);
  if (req.method === "POST" && segments.length === 1) {
    const nextUser = createUser({
      email: req.body.email || req.body.login,
      password: req.body.password,
      displayName: req.body.displayName,
      role: req.body.role || "reader"
    });
    if (auth.users.some((user) => user.email === nextUser.email)) {
      return jsonResponse(409, { message: "User already exists" });
    }
    const users = auth.users.concat(nextUser);
    await saveUsers(users);
    return jsonResponse(201, { user: publicUser(nextUser) });
  }
  const id = segments[1];
  const target = auth.users.find((user) => user.id === id || user.email === normalizeEmail(id));
  if (!target) return jsonResponse(404, { message: "User not found" });
  if (req.method === "PATCH" && segments.length === 2) {
    const role = req.body.role || target.role;
    if (!ROLES.has(role)) return jsonResponse(400, { message: "Invalid role" });
    const users = auth.users.map((user) => user.id === target.id ? {
      ...user,
      role,
      displayName: req.body.displayName !== undefined ? String(req.body.displayName || "").trim() : user.displayName
    } : user);
    await saveUsers(users);
    return jsonResponse(200, { user: publicUser(users.find((user) => user.id === target.id)) });
  }
  if (req.method === "DELETE" && segments.length === 2) {
    if (target.id === auth.user.id) return jsonResponse(400, { message: "Current user cannot be deleted" });
    await saveUsers(auth.users.filter((user) => user.id !== target.id));
    return jsonResponse(200, { ok: true });
  }
  return jsonResponse(405, { message: "Method not allowed" });
}

async function handlePlan(req, auth) {
  if (req.method === "GET") {
    const plan = await readJson(PLAN_KEY, emptyPlan());
    return jsonResponse(200, { plan });
  }
  if (req.method === "PUT" || req.method === "POST") {
    requireEditor(auth.user);
    const currentPlan = await readJson(PLAN_KEY, emptyPlan());
    const nextPlan = {
      ...normalizePlan(req.body),
      revision: Number(currentPlan.revision || 0) + 1,
      updatedAt: new Date().toISOString()
    };
    await writeJson(PLAN_KEY, nextPlan);
    return jsonResponse(200, { plan: nextPlan });
  }
  return jsonResponse(405, { message: "Method not allowed" });
}

async function handleLogs(req, auth) {
  if (req.method === "GET") {
    const logs = pruneLogs(await readJson(LOGS_KEY, []));
    if (logs.length) await writeJson(LOGS_KEY, logs);
    return jsonResponse(200, { logs: logs.slice(0, 300) });
  }
  if (req.method === "POST") {
    const logs = pruneLogs(await readJson(LOGS_KEY, []));
    const log = {
      id: req.body.id || crypto.randomUUID(),
      createdAt: req.body.createdAt || new Date().toISOString(),
      userId: auth.user.id,
      userName: auth.user.displayName || auth.user.email,
      userEmail: auth.user.email,
      action: String(req.body.action || ""),
      entityType: String(req.body.entityType || ""),
      entityId: String(req.body.entityId || ""),
      title: String(req.body.title || ""),
      details: req.body.details && typeof req.body.details === "object" ? req.body.details : {}
    };
    await writeJson(LOGS_KEY, pruneLogs([log].concat(logs)));
    return jsonResponse(201, { log });
  }
  return jsonResponse(405, { message: "Method not allowed" });
}

function activePresence(presence) {
  const cutoff = Date.now() - 90 * 1000;
  return Object.values(presence || {})
    .filter((user) => Date.parse(user.lastSeen || "") >= cutoff)
    .sort((a, b) => String(a.displayName || a.email).localeCompare(String(b.displayName || b.email), "ru"));
}

async function handlePresence(req, auth) {
  const presence = await readJson(PRESENCE_KEY, {});
  if (req.method === "POST") {
    presence[auth.user.id] = {
      id: auth.user.id,
      login: auth.user.email,
      email: auth.user.email,
      displayName: auth.user.displayName || "",
      role: auth.user.role,
      lastSeen: new Date().toISOString()
    };
    await writeJson(PRESENCE_KEY, presence);
  }
  if (req.method === "GET" || req.method === "POST") {
    return jsonResponse(200, { users: activePresence(presence) });
  }
  return jsonResponse(405, { message: "Method not allowed" });
}

async function route(req) {
  assertConfig();
  if (req.method === "OPTIONS") return textResponse(204, "");
  if (req.path === "/health") return jsonResponse(200, { ok: true, service: "brew-planner-yandex-api" });
  if (req.path === "/auth/login" && req.method === "POST") return handleLogin(req);
  const auth = await requireUser(req);
  if (req.path === "/auth/me" && req.method === "GET") return jsonResponse(200, { user: publicUser(auth.user) });
  if (req.path === "/plan") return handlePlan(req, auth);
  if (req.path === "/logs") return handleLogs(req, auth);
  if (req.path === "/presence") return handlePresence(req, auth);
  if (req.path === "/users" || req.path.startsWith("/users/")) return handleUsers(req, auth);
  return jsonResponse(404, { message: "Not found" });
}

module.exports.handler = async function handler(event) {
  try {
    return await route(parseEvent(event || {}));
  } catch (error) {
    console.error(error);
    return jsonResponse(error.statusCode || 500, { message: error.message || "Internal error" });
  }
};
