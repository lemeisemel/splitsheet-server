// Splitsheet backend — handles Roblox OAuth login and asset uploads.
//
// Flow:
//   1. Player clicks "Connect Roblox" on the website -> browser goes to /login
//   2. /login redirects to Roblox's authorize screen
//   3. Roblox sends the player back to /callback with a code
//   4. /callback exchanges the code for tokens, saves them (keyed by Roblox user id),
//      and sets a signed session cookie so the browser knows who they are next time
//   5. Website calls /upload with an image; server looks up the saved token for that
//      session, refreshes it if needed, and uploads the image to Roblox on the
//      player's behalf, returning the new asset ID.

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const {
  ROBLOX_CLIENT_ID,
  ROBLOX_CLIENT_SECRET,
  REDIRECT_URI,           // e.g. https://your-app.onrender.com/callback
  SESSION_SECRET,         // random long string, used to sign session cookies
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
  ALLOWED_ORIGIN,         // e.g. https://emelepiqgamer.github.io
  OWNER_ROBLOX_USERNAME,  // e.g. EmelLostAccount — the only account that can flip the restrict toggle
  PORT = 3000,
} = process.env;

for (const [name, val] of Object.entries({
  ROBLOX_CLIENT_ID, ROBLOX_CLIENT_SECRET, REDIRECT_URI,
  SESSION_SECRET, SUPABASE_URL, SUPABASE_SERVICE_KEY, ALLOWED_ORIGIN,
})) {
  if (!val) {
    console.error(`Missing required environment variable: ${name}`);
    process.exit(1);
  }
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const app = express();
app.use(cookieParser());
app.use(express.json({ limit: '25mb' })); // tiles can be sizable

// ---- CORS: only allow requests from your GitHub Pages site ----
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const ROBLOX_AUTHORIZE_URL = 'https://apis.roblox.com/oauth/v1/authorize';
const ROBLOX_TOKEN_URL = 'https://apis.roblox.com/oauth/v1/token';
const ROBLOX_USERINFO_URL = 'https://apis.roblox.com/oauth/v1/userinfo';
const ROBLOX_ASSETS_URL = 'https://apis.roblox.com/assets/v1/assets';

const SCOPES = 'openid profile asset:read asset:write';

// ---- tiny session helper: signed cookie holding just the Roblox user id ----
function sign(value) {
  const h = crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');
  return `${value}.${h}`;
}
function unsign(signed) {
  if (!signed) return null;
  const idx = signed.lastIndexOf('.');
  if (idx === -1) return null;
  const value = signed.slice(0, idx);
  const expected = sign(value);
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signed))
    ? value
    : null;
}

// Reads the session token from either the Authorization header (primary —
// works regardless of cross-site cookie settings) or the cookie (fallback
// for browsers that do accept it), and returns the verified Roblox user id.
function getUserId(req) {
  const authHeader = req.headers.authorization || '';
  const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  return unsign(bearer) || unsign(req.cookies.splitsheet_session);
}

// ---------------------------------------------------------------------------
// Owner-only "restrict this tool" toggle
// ---------------------------------------------------------------------------
async function isOwnerUserId(robloxUserId) {
  if (!OWNER_ROBLOX_USERNAME || !robloxUserId) return false;
  const { data } = await supabase
    .from('roblox_sessions')
    .select('username')
    .eq('roblox_user_id', robloxUserId)
    .single();
  return !!(data && data.username &&
    data.username.toLowerCase() === OWNER_ROBLOX_USERNAME.toLowerCase());
}

async function getRestrictEnabled() {
  const { data } = await supabase
    .from('app_settings')
    .select('restrict_enabled')
    .eq('id', 1)
    .single();
  return !!(data && data.restrict_enabled);
}

async function setRestrictEnabled(enabled) {
  await supabase
    .from('app_settings')
    .upsert({ id: 1, restrict_enabled: enabled, updated_at: new Date().toISOString() });
}

// In-memory store for short-lived PKCE state (fine for a small tool; not persisted).
const pendingLogins = new Map(); // state -> { codeVerifier, createdAt }

function randomToken(len = 32) {
  return crypto.randomBytes(len).toString('base64url');
}

// ---------------------------------------------------------------------------
// GET /login — kick off the Roblox OAuth flow
// ---------------------------------------------------------------------------
app.get('/login', (req, res) => {
  const state = randomToken();
  const codeVerifier = randomToken(48);
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  // Where to send the player back to once login finishes. Must live on the
  // allowed origin — otherwise this endpoint could be used to redirect
  // people to an attacker-controlled page after a real Roblox login.
  const requestedReturnTo = req.query.return_to;
  const returnTo = (requestedReturnTo && requestedReturnTo.startsWith(ALLOWED_ORIGIN))
    ? requestedReturnTo
    : ALLOWED_ORIGIN;

  pendingLogins.set(state, { codeVerifier, returnTo, createdAt: Date.now() });

  // Clean up old pending logins (older than 10 minutes)
  for (const [key, val] of pendingLogins) {
    if (Date.now() - val.createdAt > 10 * 60 * 1000) pendingLogins.delete(key);
  }

  const url = new URL(ROBLOX_AUTHORIZE_URL);
  url.searchParams.set('client_id', ROBLOX_CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', SCOPES);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');

  res.redirect(url.toString());
});

// ---------------------------------------------------------------------------
// GET /callback — Roblox redirects back here after the player logs in
// ---------------------------------------------------------------------------
app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(`Roblox login failed: ${error}`);
  }

  const pending = pendingLogins.get(state);
  if (!pending) {
    return res.status(400).send('Login session expired or invalid. Please try again.');
  }
  pendingLogins.delete(state);

  try {
    const tokenRes = await fetch(ROBLOX_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: ROBLOX_CLIENT_ID,
        client_secret: ROBLOX_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        code_verifier: pending.codeVerifier,
      }),
    });

    if (!tokenRes.ok) {
      const text = await tokenRes.text();
      console.error('Token exchange failed:', text);
      return res.status(502).send('Could not complete login with Roblox.');
    }

    const tokens = await tokenRes.json();
    // tokens: { access_token, refresh_token, id_token, expires_in, ... }

    const userInfoRes = await fetch(ROBLOX_USERINFO_URL, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const userInfo = await userInfoRes.json();
    const robloxUserId = userInfo.sub; // Roblox user ID as a string

    const expiresAt = new Date(Date.now() + tokens.expires_in * 1000).toISOString();

    const { error: dbError } = await supabase
      .from('roblox_sessions')
      .upsert({
        roblox_user_id: robloxUserId,
        username: userInfo.preferred_username || userInfo.nickname || null,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: expiresAt,
        updated_at: new Date().toISOString(),
      }, { onConflict: 'roblox_user_id' });

    if (dbError) {
      console.error('DB upsert failed:', dbError);
      return res.status(500).send('Could not save your login. Please try again.');
    }

    const sessionToken = sign(robloxUserId);

    // Cookie is a bonus for browsers that allow cross-site cookies; the
    // fragment token below is what the frontend actually relies on, since
    // most mobile browsers block third-party cookies between this domain
    // and the GitHub Pages domain.
    res.cookie('splitsheet_session', sessionToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 1000 * 60 * 60 * 24 * 90, // 90 days
    });

    // Redirect straight back to the site — no "close this tab" dead end.
    // The token rides in the URL fragment (#st=...), which browsers never
    // send to any server, so it never lands in Render's request logs.
    const dest = new URL(pending.returnTo);
    dest.hash = `st=${encodeURIComponent(sessionToken)}`;
    res.redirect(dest.toString());
  } catch (err) {
    console.error('Callback error:', err);
    res.status(500).send('Something went wrong finishing login.');
  }
});

// ---------------------------------------------------------------------------
// GET /me — lets the frontend check if the current visitor is logged in
// ---------------------------------------------------------------------------
app.get('/me', async (req, res) => {
  const userId = getUserId(req);
  const restrictEnabled = await getRestrictEnabled();

  if (!userId) return res.json({ loggedIn: false, restrictEnabled, isOwner: false });

  const { data, error } = await supabase
    .from('roblox_sessions')
    .select('roblox_user_id, username')
    .eq('roblox_user_id', userId)
    .single();

  if (error || !data) return res.json({ loggedIn: false, restrictEnabled, isOwner: false });

  const isOwner = !!(OWNER_ROBLOX_USERNAME && data.username &&
    data.username.toLowerCase() === OWNER_ROBLOX_USERNAME.toLowerCase());

  res.json({
    loggedIn: true,
    username: data.username,
    userId: data.roblox_user_id,
    restrictEnabled,
    isOwner,
  });
});

// ---------------------------------------------------------------------------
// POST /admin/restrict — owner-only toggle for "only I can upload" mode.
// Body: { enabled: true|false }
// ---------------------------------------------------------------------------
app.post('/admin/restrict', async (req, res) => {
  const userId = getUserId(req);
  if (!userId) return res.status(401).json({ error: 'Not logged in.' });

  const owner = await isOwnerUserId(userId);
  if (!owner) return res.status(403).json({ error: 'Only the owner account can change this.' });

  const enabled = !!req.body.enabled;
  await setRestrictEnabled(enabled);
  res.json({ ok: true, restrictEnabled: enabled });
});

// ---------------------------------------------------------------------------
// POST /logout
// ---------------------------------------------------------------------------
app.post('/logout', (req, res) => {
  res.clearCookie('splitsheet_session');
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Helper: get a valid access token for a session, refreshing if expired
// ---------------------------------------------------------------------------
async function getValidAccessToken(robloxUserId) {
  const { data, error } = await supabase
    .from('roblox_sessions')
    .select('*')
    .eq('roblox_user_id', robloxUserId)
    .single();

  if (error || !data) throw new Error('No saved session for this user');

  const expiresAt = new Date(data.expires_at).getTime();
  const stillValid = expiresAt - Date.now() > 60 * 1000; // 1 min buffer

  if (stillValid) return data.access_token;

  // Refresh the token
  const refreshRes = await fetch(ROBLOX_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: ROBLOX_CLIENT_ID,
      client_secret: ROBLOX_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token: data.refresh_token,
    }),
  });

  if (!refreshRes.ok) {
    throw new Error('Refresh token invalid — user needs to log in again');
  }

  const refreshed = await refreshRes.json();
  const newExpiresAt = new Date(Date.now() + refreshed.expires_in * 1000).toISOString();

  await supabase
    .from('roblox_sessions')
    .update({
      access_token: refreshed.access_token,
      refresh_token: refreshed.refresh_token || data.refresh_token,
      expires_at: newExpiresAt,
      updated_at: new Date().toISOString(),
    })
    .eq('roblox_user_id', robloxUserId);

  return refreshed.access_token;
}

// ---------------------------------------------------------------------------
// POST /upload — receives one tile image (base64) and uploads it to Roblox
// Body: { imageBase64: "...", filename: "tile_01.png" }
// ---------------------------------------------------------------------------
app.post('/upload', async (req, res) => {
  const userId = getUserId(req);
  if (!userId) {
    return res.status(401).json({ error: 'Not logged in. Please connect your Roblox account first.' });
  }

  if (await getRestrictEnabled() && !(await isOwnerUserId(userId))) {
    return res.status(403).json({ error: 'This tool is currently restricted to its owner.' });
  }

  const { imageBase64, filename } = req.body;
  if (!imageBase64) {
    return res.status(400).json({ error: 'No image provided.' });
  }

  try {
    const accessToken = await getValidAccessToken(userId);

    const imageBuffer = Buffer.from(imageBase64, 'base64');
    const requestPayload = {
      assetType: 'Decal',
      displayName: (filename || 'livery-tile').replace(/\.[^/.]+$/, '').slice(0, 50),
      description: 'Uploaded via Splitsheet',
      creationContext: {
        creator: { userId: userId },
      },
    };

    const form = new FormData();
    form.append('request', JSON.stringify(requestPayload));
    form.append('fileContent', new Blob([imageBuffer], { type: 'image/png' }), filename || 'tile.png');

    const uploadRes = await fetch(ROBLOX_ASSETS_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
      body: form,
    });

    const uploadJson = await uploadRes.json();

    if (!uploadRes.ok) {
      console.error('Upload failed:', uploadJson);
      const robloxMessage = uploadJson && (uploadJson.message || uploadJson.error);
      return res.status(502).json({
        error: robloxMessage ? `Roblox rejected the upload: ${robloxMessage}` : 'Roblox rejected the upload.',
        details: uploadJson,
      });
    }

    // Uploads are async — Roblox returns an operation to poll.
    res.json({ ok: true, operation: uploadJson });
  } catch (err) {
    console.error('Upload error:', err.message);
    if (err.message.includes('log in again')) {
      res.clearCookie('splitsheet_session');
      return res.status(401).json({ error: 'Your Roblox session expired. Please reconnect.' });
    }
    res.status(500).json({ error: 'Upload failed.', details: err.message });
  }
});

// ---------------------------------------------------------------------------
// GET /upload-status/:operationId — poll an upload operation for its asset ID
// ---------------------------------------------------------------------------
app.get('/upload-status/:operationId', async (req, res) => {
  const userId = getUserId(req);
  if (!userId) return res.status(401).json({ error: 'Not logged in.' });

  if (await getRestrictEnabled() && !(await isOwnerUserId(userId))) {
    return res.status(403).json({ error: 'This tool is currently restricted to its owner.' });
  }

  try {
    const accessToken = await getValidAccessToken(userId);
    const opRes = await fetch(
      `https://apis.roblox.com/assets/v1/operations/${req.params.operationId}`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const opJson = await opRes.json();
    res.json(opJson);
  } catch (err) {
    res.status(500).json({ error: 'Could not check upload status.', details: err.message });
  }
});

app.get('/', (req, res) => {
  res.send('Splitsheet backend is running.');
});

app.listen(PORT, () => {
  console.log(`Splitsheet backend listening on port ${PORT}`);
});
