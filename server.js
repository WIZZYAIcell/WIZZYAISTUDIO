import crypto from 'crypto';
import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const app = express();
const port = Number(process.env.PORT) || 3000;
const rootDir = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(rootDir, 'public');
const authSecret = process.env.AUTH_SECRET || '';
const publicUrl = process.env.PUBLIC_URL || '';
const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
const xClientId = process.env.X_CLIENT_ID || '';
const xClientSecret = process.env.X_CLIENT_SECRET || '';
const sessionCookie = 'wizzy_session';
const sessionLifetimeSeconds = 7 * 24 * 60 * 60;

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self'; base-uri 'self'; form-action 'self' https://accounts.google.com https://x.com; frame-ancestors 'none'",
  });
  next();
});

function productionCookie() {
  return process.env.NODE_ENV === 'production';
}

function cookieOptions(pathname, maxAge) {
  return [
    `Path=${pathname}`,
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
    ...(productionCookie() ? ['Secure'] : []),
  ].join('; ');
}

function appendCookie(res, name, value, options) {
  const previous = res.getHeader('Set-Cookie');
  const cookie = `${name}=${value}; ${options}`;
  res.setHeader('Set-Cookie', previous ? [...[].concat(previous), cookie] : cookie);
}

function clearCookie(res, name, pathname) {
  appendCookie(res, name, '', cookieOptions(pathname, 0));
}

function readCookie(req, name) {
  const cookies = req.headers.cookie || '';
  for (const item of cookies.split(';')) {
    const separator = item.indexOf('=');
    if (separator < 0) continue;
    if (item.slice(0, separator).trim() === name) return item.slice(separator + 1).trim();
  }
  return '';
}

function signPayload(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', authSecret).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function verifyPayload(value) {
  if (!authSecret || typeof value !== 'string') return null;
  const parts = value.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;

  const expected = crypto.createHmac('sha256', authSecret).update(parts[0]).digest();
  let provided;
  try {
    provided = Buffer.from(parts[1], 'base64url');
  } catch {
    return null;
  }
  if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) return null;

  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    return payload && Number.isInteger(payload.expiresAt) && payload.expiresAt > Date.now() ? payload : null;
  } catch {
    return null;
  }
}

function getPublicOrigin() {
  if (!publicUrl) return null;
  try {
    const parsed = new URL(publicUrl);
    if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) return null;
    if (productionCookie() && parsed.protocol !== 'https:') return null;
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

function callbackUrl(provider) {
  const origin = getPublicOrigin();
  if (!origin) return null;
  return `${origin}/auth/${provider}/callback`;
}

function providerEnabled(provider) {
  return Boolean(
    authSecret.length >= 32 &&
    getPublicOrigin() &&
    (provider === 'google'
      ? googleClientId && googleClientSecret
      : provider === 'x' && xClientId)
  );
}

function getSession(req) {
  const payload = verifyPayload(readCookie(req, sessionCookie));
  if (!payload || payload.issuer !== 'wizzy' || !['google', 'x'].includes(payload.provider)) return null;
  if (typeof payload.userId !== 'string' || typeof payload.name !== 'string') return null;
  return {
    provider: payload.provider,
    userId: payload.userId,
    name: payload.name,
    email: typeof payload.email === 'string' ? payload.email : null,
    username: typeof payload.username === 'string' ? payload.username : null,
    image: typeof payload.image === 'string' ? payload.image : null,
  };
}

function setOAuthState(res, provider, state, codeVerifier) {
  const cookieName = `wizzy_oauth_${provider}`;
  const value = signPayload({
    issuer: 'wizzy-oauth',
    provider,
    state,
    codeVerifier,
    expiresAt: Date.now() + 10 * 60 * 1000,
  });
  appendCookie(res, cookieName, value, cookieOptions('/auth', 600));
}

function consumeOAuthState(req, res, provider, receivedState) {
  const cookieName = `wizzy_oauth_${provider}`;
  const payload = verifyPayload(readCookie(req, cookieName));
  clearCookie(res, cookieName, '/auth');
  if (!payload || payload.issuer !== 'wizzy-oauth' || payload.provider !== provider) return null;
  if (typeof payload.state !== 'string' || typeof receivedState !== 'string') return null;

  const expected = Buffer.from(payload.state);
  const received = Buffer.from(receivedState);
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) return null;
  return payload;
}

function authFailure(res, reason) {
  const result = new URL('/', 'https://wizzy.invalid');
  result.searchParams.set('authError', reason);
  res.redirect(303, `${result.pathname}${result.search}`);
}

function authUnavailable(res) {
  res.status(503).type('text').send(
    'Sign-in is not configured. Add the required OAuth credentials, AUTH_SECRET, and PUBLIC_URL in the hosting dashboard.'
  );
}

function parseProviderResponse(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('The identity provider returned an invalid response.');
  }
}

async function exchangeGoogleCode(code) {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: googleClientId,
      client_secret: googleClientSecret,
      redirect_uri: callbackUrl('google'),
      grant_type: 'authorization_code',
    }),
  });
  const token = parseProviderResponse(await response.text());
  if (!response.ok || typeof token.access_token !== 'string') {
    throw new Error('Google could not complete sign-in.');
  }

  const profileResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
    headers: { Authorization: `Bearer ${token.access_token}` },
  });
  const profile = parseProviderResponse(await profileResponse.text());
  if (!profileResponse.ok || typeof profile.sub !== 'string') {
    throw new Error('Google did not return a valid account profile.');
  }
  if (profile.email_verified === false) throw new Error('Verify your Google email before signing in.');
  return {
    provider: 'google',
    userId: profile.sub,
    name: typeof profile.name === 'string' ? profile.name.slice(0, 100) : 'Google user',
    email: typeof profile.email === 'string' ? profile.email.slice(0, 254) : null,
    username: null,
    image: typeof profile.picture === 'string' ? profile.picture.slice(0, 2048) : null,
  };
}

async function exchangeXCode(code, codeVerifier) {
  const body = new URLSearchParams({
    code,
    grant_type: 'authorization_code',
    redirect_uri: callbackUrl('x'),
    code_verifier: codeVerifier,
  });
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (xClientSecret) {
    headers.Authorization = `Basic ${Buffer.from(`${xClientId}:${xClientSecret}`).toString('base64')}`;
  } else {
    body.set('client_id', xClientId);
  }

  const response = await fetch('https://api.x.com/2/oauth2/token', {
    method: 'POST',
    headers,
    body,
  });
  const token = parseProviderResponse(await response.text());
  if (!response.ok || typeof token.access_token !== 'string') {
    throw new Error('X could not complete sign-in.');
  }

  const profileResponse = await fetch(
    'https://api.x.com/2/users/me?user.fields=profile_image_url',
    { headers: { Authorization: `Bearer ${token.access_token}` } }
  );
  const result = parseProviderResponse(await profileResponse.text());
  const profile = result.data;
  if (!profileResponse.ok || typeof profile?.id !== 'string' || typeof profile.username !== 'string') {
    throw new Error('X did not return a valid account profile.');
  }
  return {
    provider: 'x',
    userId: profile.id,
    name: typeof profile.name === 'string' ? profile.name.slice(0, 100) : profile.username,
    email: null,
    username: profile.username.slice(0, 100),
    image: typeof profile.profile_image_url === 'string' ? profile.profile_image_url.slice(0, 2048) : null,
  };
}

function establishSession(res, profile) {
  const value = signPayload({
    issuer: 'wizzy',
    provider: profile.provider,
    userId: profile.userId,
    name: profile.name,
    email: profile.email,
    username: profile.username,
    image: profile.image,
    expiresAt: Date.now() + sessionLifetimeSeconds * 1000,
  });
  appendCookie(res, sessionCookie, value, cookieOptions('/', sessionLifetimeSeconds));
}

app.use(express.static(publicDir, { dotfiles: 'deny', index: false, fallthrough: true }));

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    hostedAiEnabled: false,
    generationEnabled: false,
    signInConfigured: {
      google: providerEnabled('google'),
      x: providerEnabled('x'),
    },
  });
});

app.get('/api/auth/providers', (_req, res) => {
  res.json({
    google: { enabled: providerEnabled('google'), label: 'Google' },
    x: { enabled: providerEnabled('x'), label: 'X' },
    instagram: {
      enabled: false,
      reason: 'Instagram sign-in requires a Meta app and currently supports professional-account flows, not general consumer login.',
    },
  });
});

app.get('/api/auth/session', (req, res) => {
  res.set('Cache-Control', 'no-store');
  return res.json({ user: getSession(req) });
});

app.get('/auth/google', (req, res) => {
  if (!providerEnabled('google')) return authUnavailable(res);

  const state = crypto.randomBytes(32).toString('base64url');
  setOAuthState(res, 'google', state, '');
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.search = new URLSearchParams({
    client_id: googleClientId,
    redirect_uri: callbackUrl('google'),
    response_type: 'code',
    scope: 'openid email profile',
    state,
    prompt: 'select_account',
  }).toString();
  return res.redirect(url.toString());
});

app.get('/auth/google/callback', async (req, res) => {
  const oauth = consumeOAuthState(req, res, 'google', req.query.state);
  if (!oauth) return authFailure(res, 'state');
  if (req.query.error) return authFailure(res, 'cancelled');
  if (!providerEnabled('google') || typeof req.query.code !== 'string') return authFailure(res, 'google');

  try {
    const profile = await exchangeGoogleCode(req.query.code);
    establishSession(res, profile);
    return res.redirect(303, '/');
  } catch (error) {
    console.error('Google sign-in failed:', error.message);
    return authFailure(res, 'google');
  }
});

app.get('/auth/x', (req, res) => {
  if (!providerEnabled('x')) return authUnavailable(res);

  const state = crypto.randomBytes(32).toString('base64url');
  const codeVerifier = crypto.randomBytes(48).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  setOAuthState(res, 'x', state, codeVerifier);
  const url = new URL('https://x.com/i/oauth2/authorize');
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: xClientId,
    redirect_uri: callbackUrl('x'),
    scope: 'users.read',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  }).toString();
  return res.redirect(url.toString());
});

app.get('/auth/x/callback', async (req, res) => {
  const oauth = consumeOAuthState(req, res, 'x', req.query.state);
  if (!oauth) return authFailure(res, 'state');
  if (req.query.error) return authFailure(res, 'cancelled');
  if (!providerEnabled('x') || typeof req.query.code !== 'string' || typeof oauth.codeVerifier !== 'string') {
    return authFailure(res, 'x');
  }

  try {
    const profile = await exchangeXCode(req.query.code, oauth.codeVerifier);
    establishSession(res, profile);
    return res.redirect(303, '/');
  } catch (error) {
    console.error('X sign-in failed:', error.message);
    return authFailure(res, 'x');
  }
});

app.post('/auth/logout', (req, res) => {
  const origin = req.get('origin');
  if (!origin || origin !== getPublicOrigin()) {
    return res.status(403).json({ error: 'Sign-out request had an invalid origin.' });
  }
  clearCookie(res, sessionCookie, '/');
  return res.status(204).end();
});

app.post('/api/chat', (_req, res) => {
  return res.status(410).json({
    error: 'Hosted AI chat is disabled in this no-provider-cost launch.',
  });
});

app.get('/api/*', (_req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.get('*', (_req, res) => res.sendFile(path.join(publicDir, 'index.html')));

app.listen(port, () => {
  console.log(`Wizzy AI is running at http://localhost:${port}`);
});
