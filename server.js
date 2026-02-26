// server.js
require("dotenv").config();
const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const fetch = require("node-fetch");
const platformClient = require("purecloud-platform-client-v2");

const config = require("./public/config");

const app = express();

app.use(express.json());
app.use(cookieParser(config.cookieSecret));
app.use(express.static(path.join(__dirname, "public")));

const client = platformClient.ApiClient.instance;
client.setEnvironment(config.region);

// Helpers
function normalizeRegion(input) {
  return input
    .replace(/^https?:\/\//, "")
    .replace(/^apps\./, "")
    .replace(/\/$/, "");
}

function base64UrlEncode(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function getBearerToken(req) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

// PKCE verifier store keyed by state (avoids cookies in iframes)
const pkceStore = new Map(); // state -> { verifier, expiresAt }

function storeVerifierForState(state, verifier, ttlMs = 5 * 60 * 1000) {
  const expiresAt = Date.now() + ttlMs;
  pkceStore.set(state, { verifier, expiresAt });
  setTimeout(() => {
    const entry = pkceStore.get(state);
    if (entry && entry.expiresAt <= Date.now()) pkceStore.delete(state);
  }, ttlMs + 2000);
}

function consumeVerifierForState(state) {
  const entry = pkceStore.get(state);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    pkceStore.delete(state);
    return null;
  }
  pkceStore.delete(state);
  return entry.verifier;
}

/**
 * 1) PKCE start (iframe-friendly)
 */
app.get("/auth/start", (req, res) => {
  const region = normalizeRegion(config.region);

  const codeVerifier = base64UrlEncode(crypto.randomBytes(48));
  const sha256 = crypto.createHash("sha256").update(codeVerifier).digest();
  const codeChallenge = base64UrlEncode(sha256);

  const state = base64UrlEncode(crypto.randomBytes(16)) + "_" + Date.now();
  storeVerifierForState(state, codeVerifier);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: "conversations",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
  });

  const authUrl = `https://login.${region}/oauth/authorize?${params.toString()}`;
  console.log("AUTH URL:", authUrl);
  res.redirect(authUrl);
});

/**
 * 2) PKCE callback: exchange code for token, store token in iframe localStorage, return to app
 */
app.get("/oauth/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res
        .status(400)
        .send(`OAuth error: ${error} - ${error_description || ""}`);
    }
    if (!code) return res.status(400).send("Missing authorization code");
    if (!state) return res.status(400).send("Missing state");

    const codeVerifier = consumeVerifierForState(state);
    if (!codeVerifier) {
      return res
        .status(400)
        .send("PKCE verifier missing (expired or invalid state)");
    }

    const region = normalizeRegion(config.region);
    const tokenUrl = `https://login.${region}/oauth/token`;

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: config.redirectUri,
      client_id: config.clientId,
      code_verifier: codeVerifier,
    });

    const tokenResp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    const tokenJson = await tokenResp.json();
    if (!tokenResp.ok) {
      console.error("Token exchange failed:", tokenResp.status, tokenJson);
      return res
        .status(500)
        .send(`Token exchange failed: ${JSON.stringify(tokenJson)}`);
    }

    // Store token in localStorage in the widget iframe, then navigate back to /
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(`<!doctype html>
<html>
  <body>
    <script>
      (function () {
        var tokenData = ${JSON.stringify({
          access_token: tokenJson.access_token,
          expires_in: tokenJson.expires_in,
          token_type: tokenJson.token_type,
        })};

        try {
          window.localStorage.setItem("gcAccessToken", JSON.stringify(tokenData));
        } catch (e) {}

        window.location.replace("/");
      })();
    </script>
  </body>
</html>`);
  } catch (e) {
    console.error("OAuth callback error:", e);
    res.status(500).send("OAuth callback error: " + String(e));
  }
});

/**
 * 3) Logout: nothing server-side to clear, but could be used to clear server-side session if that were used instead of localStorage
 */
app.post("/auth/logout", (req, res) => {
  res.json({ ok: true });
});

/**
 * 4) Debug endpoint: who am I (user context)
 */
app.get("/api/me", async (req, res) => {
  try {
    console.log(
      "Authorization header:",
      req.headers.authorization ? "present" : "missing",
    );
    const token = getBearerToken(req);
    if (!token)
      return res.status(401).json({ ok: false, message: "Not logged in" });

    client.setAccessToken(token);
    const usersApi = new platformClient.UsersApi();
    const me = await usersApi.getUsersMe();
    return res.json({ ok: true, me });
  } catch (e) {
    const status = e?.status || e?.response?.status || 500;
    return res.status(status).json({
      ok: false,
      message: e?.message || "Genesys API error",
      status,
      body: e?.body || e?.response?.data,
    });
  }
});

/**
 * 5) Place call + return conversation id
 */
app.post("/api/call", async (req, res) => {
  try {
    console.log(
      "Authorization header:",
      req.headers.authorization ? "present" : "missing",
    );
    const token = getBearerToken(req);
    if (!token)
      return res.status(401).json({ ok: false, message: "Not logged in" });

    const phoneNumber = req.body.phoneNumber;
    if (!phoneNumber)
      return res
        .status(400)
        .json({ ok: false, message: "phoneNumber required" });

    client.setAccessToken(token);
    const conversationsApi = new platformClient.ConversationsApi();

    const result = await conversationsApi.postConversationsCalls({
      phoneNumber,
    });

    res.json({ ok: true, conversationId: result.id, raw: result });
  } catch (e) {
    res.status(e?.status || 500).json({
      ok: false,
      message: "Failed to place call",
      status: e?.status,
      sdkMessage: e?.message,
      apiBody: e?.body,
    });
  }
});

/** Helpers */
app.get("/config", (req, res) => {
  res.json({
    callNumber: process.env.CALL_NUMBER || "",
  });
});
app.get("/health", (req, res) => res.json({ ok: true, region: config.region }));

app.listen(config.port, () => {
  console.log(`Server running: http://localhost:${config.port}`);
});
