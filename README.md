# Wizzy AI

Wizzy is a responsive, sign-in-gated public demo. It currently supports Google and X OAuth when configured. It does not call a hosted AI provider, so it cannot spend Hugging Face inference credits. Chat, image/video generation, subscriptions, and credit purchases are deliberately disabled in this release.

The layout supports current desktop and mobile browsers, including Android and iOS browsers. Signing in requires provider setup; Instagram personal-account sign-in is not supported here. Instagram's current login products are intended for professional accounts and require a separate Meta app integration.

## Run locally

1. Install Node.js 18 or later.
2. If you do not already have a `.env` file, copy `.env.example` to `.env`. If one already exists, add the needed settings without replacing its contents.
3. Set a random `AUTH_SECRET` of at least 32 characters and `PUBLIC_URL=http://localhost:3000`.
4. To test Google or X sign-in locally, create OAuth apps with the exact callback URLs listed below and fill their client credentials in `.env`.
5. Start with `npm install` and `npm start`, then visit `http://localhost:3000`.

Generate a secret with:

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

### OAuth callback URLs

- Google: `PUBLIC_URL/auth/google/callback`
- X: `PUBLIC_URL/auth/x/callback`

Replace `PUBLIC_URL` with the exact HTTPS Render address when deployed. Configure the same full callback URL in each provider's developer console. Google sign-in uses the OpenID Connect `openid email profile` scopes. X sign-in requests `users.read` and PKCE.

OAuth credentials and `AUTH_SECRET` are server-side secrets. Never commit them, put them in the public directory, or send them to the browser.

## Public deployment on Render

1. Push this project to a GitHub repository you control.
2. In Render, create a Web Service from the repository. Choose `npm install` as the build command and `npm start` as the start command. The included `render.yaml` selects the free instance plan.
3. Deploy once to get the Render URL.
4. In Render's environment settings, set `PUBLIC_URL` to that exact HTTPS URL; set a random `AUTH_SECRET` and the OAuth client ID/secret values for providers you have configured.
5. Add the matching callback URLs to the Google and/or X OAuth apps, save the Render environment changes, and redeploy.

Provider OAuth apps may require verification, developer enrollment, test users, or other setup. A configured credential is not a guarantee that a provider will approve the app. Render's free service can sleep, has usage limits, and may change its free offering. This project has no external AI-provider or payment-provider integration, but public hosting availability is not guaranteed to be permanently free.

## Cost and feature limits

- No server-side AI provider is called. `/api/chat` deliberately returns `410 Gone`.
- No AI image/video model runs in this release. Visitor sign-in does not create free AI generations.
- OAuth sign-in creates a seven-day, signed, HTTP-only browser session. This release does not use a database, store permanent user accounts, or issue/manage credits.
- This release does not charge visitors or connect payout details to a bank. Mobile data/Wi-Fi charges go to the visitor's internet provider, not to Wizzy.
- Adding hosted generation or payments later requires a cost review, provider/payment accounts, secret configuration, and secure persistent account/credit storage.
