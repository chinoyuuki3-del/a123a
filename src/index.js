const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export default {
  async fetch(request, env) {
    const origin = request.headers.get("origin") || "";
    const cors = corsHeaders(origin, env);

    if (request.method === "OPTIONS") {
      if (!cors) return json({ ok: false, error: "origin_not_allowed" }, 403);
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/health") {
        return json({ ok: true, service: "aft-sync-api", version: "0.1.0" }, 200, cors);
      }

      if (!cors) return json({ ok: false, error: "origin_not_allowed" }, 403);

      if (request.method === "POST" && url.pathname === "/v1/register") {
        return withCors(await register(request, env), cors);
      }
      if (request.method === "POST" && url.pathname === "/v1/login") {
        return withCors(await login(request, env), cors);
      }

      const currentUser = await authenticate(request, env);
      if (!currentUser) return json({ ok: false, error: "unauthorized" }, 401, cors);
      if (currentUser.banned) return json({ ok: false, error: "banned" }, 403, cors);

      if (request.method === "GET" && url.pathname === "/v1/me") {
        return json({ ok: true, user: publicUser(currentUser) }, 200, cors);
      }
      if (request.method === "POST" && url.pathname === "/v1/logout") {
        return withCors(await logout(request, env), cors);
      }
      if (request.method === "GET" && url.pathname === "/v1/users/search") {
        return withCors(await searchUsers(url, currentUser, env), cors);
      }
      if (request.method === "POST" && url.pathname === "/v1/friends/request") {
        return withCors(await sendFriendRequest(request, currentUser, env), cors);
      }
      if (request.method === "GET" && url.pathname === "/v1/friends/requests") {
        return withCors(await listFriendRequests(currentUser, env), cors);
      }
      if (request.method === "POST" && url.pathname === "/v1/friends/accept") {
        return withCors(await acceptFriendRequest(request, currentUser, env), cors);
      }
      if (request.method === "GET" && url.pathname === "/v1/friends") {
        return withCors(await listFriends(currentUser, env), cors);
      }
      if (request.method === "POST" && url.pathname === "/v1/blocks") {
        return withCors(await blockUser(request, currentUser, env), cors);
      }
      if (request.method === "GET" && url.pathname === "/v1/sync") {
        return withCors(await getSyncState(currentUser, env), cors);
      }
      if (request.method === "PUT" && url.pathname === "/v1/sync") {
        return withCors(await putSyncState(request, currentUser, env), cors);
      }

      return json({ ok: false, error: "not_found" }, 404, cors);
    } catch (error) {
      console.error("AFT API error", error);
      return json({ ok: false, error: "server_error" }, 500, cors);
    }
  }
};

function corsHeaders(origin, env) {
  const allowed = String(env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(value => value.trim())
    .filter(Boolean);
  const localAllowed = String(env.ALLOW_LOCAL_FILE || "").toLowerCase() === "true";
  const accepted = allowed.includes("*") || allowed.includes(origin) || (!origin && localAllowed) || (origin === "null" && localAllowed);
  if (!accepted) return null;
  return {
    "access-control-allow-origin": origin || "null",
    "access-control-allow-methods": "GET,POST,PUT,OPTIONS",
    "access-control-allow-headers": "authorization,content-type",
    "access-control-max-age": "86400",
    "vary": "Origin"
  };
}

function json(body, status = 200, extraHeaders = null) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...(extraHeaders || {}) }
  });
}

function withCors(response, cors) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(cors || {})) headers.set(key, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function readJson(request, maxBytes = 32_768) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > maxBytes) throw new ApiError("payload_too_large", 413);
  const text = await request.text();
  if (encoder.encode(text).byteLength > maxBytes) throw new ApiError("payload_too_large", 413);
  try {
    return JSON.parse(text || "{}");
  } catch {
    throw new ApiError("invalid_json", 400);
  }
}

class ApiError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

async function register(request, env) {
  try {
    const body = await readJson(request);
    const username = cleanUsername(body.username);
    const password = String(body.password || "");
    if (!username) throw new ApiError("invalid_username");
    if (password.length < 8 || password.length > 128) throw new ApiError("invalid_password");

    const usernameKey = username.toLocaleLowerCase("ja-JP");
    const exists = await env.DB.prepare("SELECT 1 AS found FROM users WHERE username_key = ?")
      .bind(usernameKey)
      .first();
    if (exists) throw new ApiError("username_taken", 409);

    const id = `aft-${crypto.randomUUID()}`;
    const salt = randomBase64(16);
    const passwordHash = await derivePasswordHash(password, salt);
    const timestamp = new Date().toISOString();
    await env.DB.prepare(
      "INSERT INTO users (id, username, username_key, password_salt, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(id, username, usernameKey, salt, passwordHash, timestamp, timestamp).run();

    const token = await createSession(id, env);
    return json({ ok: true, token, user: { id, username } }, 201);
  } catch (error) {
    return apiErrorResponse(error);
  }
}

async function login(request, env) {
  try {
    const body = await readJson(request);
    const loginValue = String(body.login || "").trim();
    const password = String(body.password || "");
    if (!loginValue || !password) throw new ApiError("missing_login");

    const user = await env.DB.prepare(
      "SELECT id, username, username_key, password_salt, password_hash, banned FROM users WHERE id = ? OR username_key = ? LIMIT 1"
    ).bind(loginValue, loginValue.toLocaleLowerCase("ja-JP")).first();

    if (!user || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
      throw new ApiError("invalid_credentials", 401);
    }
    if (user.banned) throw new ApiError("banned", 403);

    const token = await createSession(user.id, env);
    return json({ ok: true, token, user: publicUser(user) });
  } catch (error) {
    return apiErrorResponse(error);
  }
}

async function logout(request, env) {
  const token = bearerToken(request);
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256Base64(token)).run();
  }
  return json({ ok: true });
}

async function authenticate(request, env) {
  const token = bearerToken(request);
  if (!token) return null;
  return env.DB.prepare(
    `SELECT u.id, u.username, u.banned
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?
      LIMIT 1`
  ).bind(await sha256Base64(token), new Date().toISOString()).first();
}

async function createSession(userId, env) {
  const token = randomBase64(32);
  const now = new Date();
  const expires = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)"
  ).bind(await sha256Base64(token), userId, now.toISOString(), expires.toISOString()).run();
  return token;
}

function bearerToken(request) {
  const match = /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") || "");
  return match ? match[1].trim() : "";
}

async function searchUsers(url, currentUser, env) {
  const query = cleanUsername(url.searchParams.get("q") || "");
  if (!query) return json({ ok: true, users: [] });
  const result = await env.DB.prepare(
    `SELECT u.id, u.username
       FROM users u
      WHERE u.banned = 0
        AND u.id <> ?
        AND (u.username_key LIKE ? OR u.id = ?)
        AND NOT EXISTS (
          SELECT 1 FROM blocks b
           WHERE (b.blocker_id = ? AND b.blocked_id = u.id)
              OR (b.blocker_id = u.id AND b.blocked_id = ?)
        )
      ORDER BY u.username_key
      LIMIT 20`
  ).bind(currentUser.id, `${query.toLocaleLowerCase("ja-JP")}%`, query, currentUser.id, currentUser.id).all();
  return json({ ok: true, users: result.results || [] });
}

async function sendFriendRequest(request, currentUser, env) {
  try {
    const body = await readJson(request);
    const targetId = String(body.targetId || "").trim();
    if (!targetId || targetId === currentUser.id) throw new ApiError("invalid_target");

    const target = await env.DB.prepare("SELECT id, banned FROM users WHERE id = ?").bind(targetId).first();
    if (!target || target.banned) throw new ApiError("user_unavailable", 404);
    if (await isBlocked(currentUser.id, targetId, env)) throw new ApiError("blocked", 403);

    const pairKey = friendPairKey(currentUser.id, targetId);
    const existing = await env.DB.prepare("SELECT id, status FROM friendships WHERE pair_key = ?")
      .bind(pairKey)
      .first();
    if (existing) return json({ ok: true, request: existing });

    const timestamp = new Date().toISOString();
    const id = `friend-${crypto.randomUUID()}`;
    await env.DB.prepare(
      "INSERT INTO friendships (id, pair_key, requester_id, receiver_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)"
    ).bind(id, pairKey, currentUser.id, targetId, timestamp, timestamp).run();
    return json({ ok: true, request: { id, status: "pending" } }, 201);
  } catch (error) {
    return apiErrorResponse(error);
  }
}

async function listFriendRequests(currentUser, env) {
  const result = await env.DB.prepare(
    `SELECT f.id, u.id AS user_id, u.username, f.created_at
       FROM friendships f
       JOIN users u ON u.id = f.requester_id
      WHERE f.receiver_id = ? AND f.status = 'pending' AND u.banned = 0
      ORDER BY f.created_at DESC`
  ).bind(currentUser.id).all();
  return json({ ok: true, requests: result.results || [] });
}

async function acceptFriendRequest(request, currentUser, env) {
  try {
    const body = await readJson(request);
    const requestId = String(body.requestId || "").trim();
    const pending = await env.DB.prepare(
      "SELECT id, requester_id FROM friendships WHERE id = ? AND receiver_id = ? AND status = 'pending'"
    ).bind(requestId, currentUser.id).first();
    if (!pending) throw new ApiError("request_not_found", 404);
    if (await isBlocked(currentUser.id, pending.requester_id, env)) throw new ApiError("blocked", 403);

    await env.DB.prepare(
      "UPDATE friendships SET status = 'accepted', updated_at = ? WHERE id = ?"
    ).bind(new Date().toISOString(), requestId).run();
    return json({ ok: true });
  } catch (error) {
    return apiErrorResponse(error);
  }
}

async function listFriends(currentUser, env) {
  const result = await env.DB.prepare(
    `SELECT u.id, u.username, f.updated_at AS friends_since
       FROM friendships f
       JOIN users u ON u.id = CASE WHEN f.requester_id = ? THEN f.receiver_id ELSE f.requester_id END
      WHERE (f.requester_id = ? OR f.receiver_id = ?)
        AND f.status = 'accepted'
        AND u.banned = 0
        AND NOT EXISTS (
          SELECT 1 FROM blocks b
           WHERE (b.blocker_id = ? AND b.blocked_id = u.id)
              OR (b.blocker_id = u.id AND b.blocked_id = ?)
        )
      ORDER BY u.username_key`
  ).bind(currentUser.id, currentUser.id, currentUser.id, currentUser.id, currentUser.id).all();
  return json({ ok: true, friends: result.results || [] });
}

async function blockUser(request, currentUser, env) {
  try {
    const body = await readJson(request);
    const targetId = String(body.targetId || "").trim();
    if (!targetId || targetId === currentUser.id) throw new ApiError("invalid_target");
    const target = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(targetId).first();
    if (!target) throw new ApiError("user_unavailable", 404);

    await env.DB.batch([
      env.DB.prepare(
        "INSERT OR IGNORE INTO blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?)"
      ).bind(currentUser.id, targetId, new Date().toISOString()),
      env.DB.prepare(
        "DELETE FROM friendships WHERE pair_key = ?"
      ).bind(friendPairKey(currentUser.id, targetId))
    ]);
    return json({ ok: true });
  } catch (error) {
    return apiErrorResponse(error);
  }
}

async function getSyncState(currentUser, env) {
  const row = await env.DB.prepare(
    "SELECT state_json, revision, updated_at FROM app_state WHERE user_id = ?"
  ).bind(currentUser.id).first();
  if (!row) return json({ ok: true, state: null, revision: 0, updatedAt: null });
  let state = null;
  try {
    state = JSON.parse(row.state_json);
  } catch {
    return json({ ok: false, error: "stored_state_invalid" }, 500);
  }
  return json({ ok: true, state, revision: row.revision, updatedAt: row.updated_at });
}

async function putSyncState(request, currentUser, env) {
  try {
    const body = await readJson(request, 262_144);
    const state = body.state;
    if (!state || typeof state !== "object" || Array.isArray(state)) throw new ApiError("invalid_state");
    const stateJson = JSON.stringify(state);
    if (encoder.encode(stateJson).byteLength > 250_000) throw new ApiError("state_too_large", 413);

    const timestamp = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO app_state (user_id, state_json, revision, updated_at)
       VALUES (?, ?, 1, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         state_json = excluded.state_json,
         revision = app_state.revision + 1,
         updated_at = excluded.updated_at`
    ).bind(currentUser.id, stateJson, timestamp).run();
    const row = await env.DB.prepare("SELECT revision FROM app_state WHERE user_id = ?")
      .bind(currentUser.id)
      .first();
    return json({ ok: true, revision: row?.revision || 1, updatedAt: timestamp });
  } catch (error) {
    return apiErrorResponse(error);
  }
}

async function isBlocked(firstId, secondId, env) {
  return Boolean(await env.DB.prepare(
    `SELECT 1 AS found FROM blocks
      WHERE (blocker_id = ? AND blocked_id = ?)
         OR (blocker_id = ? AND blocked_id = ?)
      LIMIT 1`
  ).bind(firstId, secondId, secondId, firstId).first());
}

function cleanUsername(value) {
  const username = String(value || "").trim().replace(/\s+/g, " ");
  if (username.length < 2 || username.length > 24) return "";
  if (!/^[\p{L}\p{N}_\- ]+$/u.test(username)) return "";
  return username;
}

function publicUser(user) {
  return { id: user.id, username: user.username };
}

function friendPairKey(first, second) {
  return [first, second].sort().join(":");
}

function apiErrorResponse(error) {
  if (error instanceof ApiError) return json({ ok: false, error: error.code }, error.status);
  console.error(error);
  return json({ ok: false, error: "server_error" }, 500);
}

async function derivePasswordHash(password, saltBase64) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: base64ToBytes(saltBase64),
      iterations: 210_000
    },
    key,
    256
  );
  return bytesToBase64(new Uint8Array(bits));
}

async function verifyPassword(password, salt, expectedHash) {
  const actual = base64ToBytes(await derivePasswordHash(password, salt));
  const expected = base64ToBytes(expectedHash);
  if (actual.length !== expected.length) return false;
  let difference = 0;
  for (let index = 0; index < actual.length; index += 1) difference |= actual[index] ^ expected[index];
  return difference === 0;
}

async function sha256Base64(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return bytesToBase64(new Uint8Array(digest));
}

function randomBase64(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToBase64(bytes);
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}
