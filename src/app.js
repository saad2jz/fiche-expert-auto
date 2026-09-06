import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import cors from 'cors';
import express from 'express';
import { validateChatBody, validateInlineBody } from './validation.js';
import { createAccountRouter } from './auth/account-routes.js';
import { runDraftMaintenance } from './services/draft-scheduler.js';
import { createGarageAdminRouter, createGarageApiRouter } from './marketplace/garage-routes.js';
import { renderGarageDetail, renderGarageNotFound } from './marketplace/garage-pages.js';

const DEFAULT_FRONTEND_ORIGINS = new Set([
  'https://cardiag.online',
  'https://www.cardiag.online',
  'https://fiche-expert-auto.onrender.com',
  'https://localhost',
  'capacitor://localhost',
]);
const FIREBASE_AUTH_HELPER_ORIGIN = 'https://cardiag-f1ea7.firebaseapp.com';

function isAllowedOrigin(origin) {
  if (!origin) return true;
  const configured = (process.env.FRONTEND_ORIGINS || '').split(',').map((value) => value.trim().replace(/\/$/, ''));
  const normalizedOrigin = origin.replace(/\/$/, '');
  return DEFAULT_FRONTEND_ORIGINS.has(normalizedOrigin)
    || configured.includes(normalizedOrigin)
    || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(normalizedOrigin);
}

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function sendPublicFile(res, fileName) {
  const filePath = path.join(projectRoot, fileName);
  return res.type(path.extname(fileName)).send(fs.readFileSync(filePath));
}

function firebaseProxyHeaders(req) {
  const headers = new Headers();
  for (const name of ['accept', 'accept-language', 'content-type', 'user-agent']) {
    const value = req.get(name);
    if (value) headers.set(name, value);
  }
  return headers;
}

function proxyResponseHeaders(res, upstream, canonicalOrigin) {
  // The global application policy deliberately blocks framing. Firebase's
  // reserved `/__/auth/iframe` endpoint is the one exception: its same-origin
  // iframe carries OAuth state between the app and the popup/redirect helper.
  res.removeHeader('X-Frame-Options');
  res.removeHeader('Content-Security-Policy');
  // Node décompresse les réponses fetch. Ne pas recopier content-length ni
  // content-encoding, qui décriraient alors les octets reçus en amont plutôt
  // que le corps effectivement envoyé au navigateur.
  const allowed = new Set(['content-type', 'cache-control', 'etag', 'last-modified', 'vary']);
  for (const [name, value] of upstream.headers) {
    if (allowed.has(name.toLowerCase())) res.setHeader(name, value);
  }
  const location = upstream.headers.get('location');
  if (location) {
    const rewritten = location.startsWith(FIREBASE_AUTH_HELPER_ORIGIN)
      ? `${canonicalOrigin}${location.slice(FIREBASE_AUTH_HELPER_ORIGIN.length)}`
      : location;
    res.setHeader('Location', rewritten);
  }
  const cookies = upstream.headers.getSetCookie?.() || [];
  if (cookies.length) res.setHeader('Set-Cookie', cookies);
  res.setHeader('Cache-Control', 'no-store');
}

async function proxyFirebaseAuthHelper(req, res, next, canonicalOrigin) {
  const requestPath = req.originalUrl || req.url;
  if (requestPath.startsWith('/__/firebase/init.json')) {
    res.setHeader('Cache-Control', 'no-store');
    return sendPublicFile(res, 'firebase-config.json');
  }
  const isAuthHelper = requestPath.startsWith('/__/auth/');
  if (!isAuthHelper) return next();
  try {
    const noBody = ['GET', 'HEAD'].includes(req.method);
    const upstream = await fetch(new URL(requestPath, FIREBASE_AUTH_HELPER_ORIGIN), {
      method: req.method,
      headers: firebaseProxyHeaders(req),
      body: noBody ? undefined : req,
      duplex: noBody ? undefined : 'half',
      redirect: 'manual',
    });
    proxyResponseHeaders(res, upstream, canonicalOrigin);
    return res.status(upstream.status).send(Buffer.from(await upstream.arrayBuffer()));
  } catch (error) {
    console.error(`[${req.requestId || 'unknown'}] Relais Firebase Auth indisponible:`, error.message);
    return res.status(502).json({ error: 'Le relais de connexion Firebase est temporairement indisponible.' });
  }
}

function xmlEscape(value) {
  return String(value || '').replace(/[&<>"']/g, (character) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&apos;' }[character]));
}

function sitemapDocument(origin, garages = []) {
  const pages = [
    { loc: `${origin}/`, lastmod: '' },
    { loc: `${origin}/garages`, lastmod: '' },
    ...garages.map((garage) => ({ loc: `${origin}/garages/${encodeURIComponent(garage.slug)}`, lastmod: garage.updatedAt })),
  ];
  return `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${pages.map((page) => `<url><loc>${xmlEscape(page.loc)}</loc>${page.lastmod ? `<lastmod>${xmlEscape(page.lastmod.slice(0, 10))}</lastmod>` : ''}</url>`).join('')}</urlset>`;
}

export function createRateLimiter({ windowMs = 60_000, max = 12, accountService = null } = {}) {
  const buckets = new Map();
  return async (req, res, next) => {
    let identity = `ip:${req.ip || req.socket?.remoteAddress || 'unknown'}`;
    const token = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i)?.[1];
    if (token && accountService?.verifyToken) {
      try { identity = `uid:${(await accountService.verifyToken(token)).uid}`; } catch { /* Limitation par IP si le jeton est invalide. */ }
    }
    const now = Date.now();
    const recent = (buckets.get(identity) || []).filter((timestamp) => now - timestamp < windowMs);
    if (recent.length >= max) {
      const retryAfter = Math.max(1, Math.ceil((windowMs - (now - recent[0])) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ error: 'Trop de demandes adressées à l’assistant. Réessayez dans quelques instants.', code: 'ASSISTANT_RATE_LIMITED', retryAfter });
    }
    recent.push(now);
    buckets.set(identity, recent);
    if (buckets.size > 2_000) for (const [key, values] of buckets) if (!values.some((timestamp) => now - timestamp < windowMs)) buckets.delete(key);
    return next();
  };
}

// Vercel gives precedence to `src/app.js` as a recognized Express entry file.
// Keep the factory above reusable by tests while forwarding production
// invocations to the fully configured runtime assembled in `src/server.js`.
export default async function cardiagVercelHandler(req, res) {
  const { default: runtimeApp } = await import('./server.js');
  return runtimeApp(req, res);
}

export function createApp({ llmService, accountService = null, mailService = null, stripeService = null }) {
  if (!llmService) throw new Error('llmService est requis.');
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use((req, res, next) => {
    req.requestId = crypto.randomUUID();
    res.setHeader('X-Request-Id', req.requestId);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(self), geolocation=(self), microphone=()');
    // The client intentionally uses Firebase and a CDN-hosted legacy fallback.
    // Keep the policy explicit instead of allowing arbitrary script origins.
    res.setHeader('Content-Security-Policy', [
      "default-src 'self'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "img-src 'self' data: blob: https:",
      "connect-src 'self' https://fiche-expert-auto.onrender.com https://*.googleapis.com https://*.firebaseio.com https://*.firebasestorage.app https://*.googleusercontent.com",
      "script-src 'self' 'unsafe-inline' https://www.gstatic.com https://apis.google.com https://cdnjs.cloudflare.com",
      "style-src 'self' 'unsafe-inline'",
      "frame-src 'self' https://cardiag-f1ea7.firebaseapp.com https://accounts.google.com",
      "form-action 'self' https://accounts.google.com",
      "worker-src 'self' blob:",
    ].join('; '));
    next();
  });
  const canonicalOrigin = String(process.env.PUBLIC_ORIGIN || 'https://www.cardiag.online').replace(/\/$/, '');
  const canonicalHost = new URL(canonicalOrigin).hostname;
  const alternatePageHosts = new Set(['fiche-expert-auto.onrender.com', 'cardiag.online', 'www.cardiag.online']);
  alternatePageHosts.delete(canonicalHost);
  app.use((req, res, next) => {
    const acceptsHtml = req.method === 'GET' && String(req.headers.accept || '').includes('text/html');
    if (acceptsHtml && alternatePageHosts.has(req.hostname) && req.hostname !== canonicalHost) {
      return res.redirect(308, `${canonicalOrigin}${req.originalUrl}`);
    }
    return next();
  });
  app.use(cors({
    origin: (origin, callback) => callback(null, isAllowedOrigin(origin)),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));
  // Firebase uses the canonical CarDiag origin as its first-party authDomain.
  // Relay only the reserved helper paths to Firebase Hosting so popup and
  // redirect state are not dependent on third-party browser storage.
  app.use('/__', (req, res, next) => proxyFirebaseAuthHelper(req, res, next, canonicalOrigin));
  // Stripe signe les octets bruts. Cette route doit précéder express.json().
  app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    if (!stripeService?.webhookConfigured || !accountService) return res.status(503).json({ error: 'Webhook Stripe non configuré.' });
    try {
      const event = stripeService.constructWebhookEvent(req.body, req.headers['stripe-signature']);
      const object = event.data?.object || {};
      const uid = String(object.metadata?.uid || object.client_reference_id || '');
      const premiumEvent = ['checkout.session.completed', 'customer.subscription.updated', 'customer.subscription.deleted', 'invoice.payment_failed'].includes(event.type);
      if (premiumEvent) {
        // Garage publication is deliberately independent from billing. This
        // service only updates garages.premium and never the status field.
        await accountService.updateGaragePremiumFromStripeEvent?.(event);
      }
      if (uid && premiumEvent) {
        await accountService.saveBilling(uid, {
          customerId: String(object.customer || ''), subscriptionId: String(object.subscription || object.id || ''),
          status: event.type === 'checkout.session.completed' ? 'active' : (event.type === 'invoice.payment_failed' ? 'past_due' : String(object.status || 'inactive')),
        });
      }
      return res.json({ received: true });
    } catch (error) {
      console.error(`[${req.requestId}] Webhook Stripe invalide:`, error.message);
      return res.status(400).json({ error: 'Signature Stripe invalide.' });
    }
  });
  // L'historique synchronisé est plafonné et nettoyé par le routeur de compte.
  // La limite globale reste suffisamment basse pour protéger les autres routes.
  app.use(express.json({ limit: '950kb' }));

  // Le même dossier peut être déployé sur Render : seuls les fichiers publics
  // nécessaires au frontend sont exposés, jamais .env ni le code du serveur.
  app.use('/css', express.static(path.join(projectRoot, 'css')));
  app.use('/js', express.static(path.join(projectRoot, 'js')));
  app.use('/data', express.static(path.join(projectRoot, 'data')));
  app.use('/icons', express.static(path.join(projectRoot, 'icons')));
  app.use('/assets', express.static(path.join(projectRoot, 'assets')));
  app.use('/vendor', express.static(path.join(projectRoot, 'vendor')));
  app.get('/', (_req, res) => sendPublicFile(res, 'index.html'));
  app.get('/build-data.js', (_req, res) => sendPublicFile(res, 'build-data.js'));
  app.get('/manifest.json', (_req, res) => sendPublicFile(res, 'manifest.json'));
  app.get('/firebase-config.json', (_req, res) => sendPublicFile(res, 'firebase-config.json'));
  app.get('/robots.txt', (_req, res) => sendPublicFile(res, 'robots.txt'));
  app.get('/sitemap.xml', async (_req, res) => {
    try {
      const garages = accountService?.listGarageSitemapEntries ? await accountService.listGarageSitemapEntries() : [];
      return res.type('application/xml').send(sitemapDocument(canonicalOrigin, garages));
    } catch {
      // An unavailable directory must never make the core sitemap fail.
      return res.type('application/xml').send(sitemapDocument(canonicalOrigin));
    }
  });
  app.get('/privacy.html', (_req, res) => sendPublicFile(res, 'privacy.html'));
  app.get('/terms.html', (_req, res) => sendPublicFile(res, 'terms.html'));
  app.get('/account-deletion.html', (_req, res) => sendPublicFile(res, 'account-deletion.html'));
  app.get('/privacy', (_req, res) => res.redirect(308, '/privacy.html'));
  app.get('/terms', (_req, res) => res.redirect(308, '/terms.html'));
  app.get('/account-deletion', (_req, res) => res.redirect(308, '/account-deletion.html'));
  app.get('/shared-report.html', (_req, res) => sendPublicFile(res, 'shared-report.html'));
  app.get('/garages', (_req, res) => sendPublicFile(res, 'garage-directory.html'));
  app.get('/pro/inscription-garage', (_req, res) => sendPublicFile(res, 'garage-registration.html'));
  app.get('/admin/garages', (_req, res) => sendPublicFile(res, 'garage-admin.html'));
  app.get('/garages/:slug', async (req, res) => {
    try {
      const entry = accountService?.getPublicGarage ? await accountService.getPublicGarage(String(req.params.slug || '')) : null;
      if (!entry) return res.status(404).type('html').send(renderGarageNotFound(canonicalOrigin));
      const premiumBadge = entry.garage.premium?.active ? '<p class="garage-premium-badge">Garage recommandé CarDiag</p>' : '';
      const premiumManager = `${premiumBadge}<section id="garagePremiumManager" class="garage-premium-manager" data-garage-id="${encodeURIComponent(entry.garage.id)}" hidden aria-live="polite"></section><script type="module" src="/js/marketplace/garage-premium.js"></script>`;
      return res.type('html').send(renderGarageDetail(entry.garage, entry.reviews, canonicalOrigin).replace('</main>', `${premiumManager}</main>`));
    } catch {
      return res.status(503).type('html').send(renderGarageNotFound(canonicalOrigin));
    }
  });
  // Every authenticated or local-first application page is handled by the
  // lightweight History API router. This also makes refreshes on a deep link
  // work on Render without exposing a second static-site configuration.
  app.get(/^\/app(?:\/.*)?$/, (_req, res) => sendPublicFile(res, 'index.html'));
  app.get('/exemple-rapport', (_req, res) => sendPublicFile(res, 'index.html'));
  app.get('/fiche/:id', (req, res) => res.redirect(308, `/app/inspection/${encodeURIComponent(req.params.id)}/rapport`));
  app.get('/r/:id', (_req, res) => sendPublicFile(res, 'shared-report.html'));
  app.get('/.well-known/assetlinks.json', (_req, res) => {
    const fingerprints = String(process.env.ANDROID_APP_LINK_SHA256 || '')
      .split(',').map((value) => value.trim()).filter(Boolean);
    if (!fingerprints.length) return res.status(404).json({ error: 'Empreinte App Links non configurée.' });
    return res.json([{
      relation: ['delegate_permission/common.handle_all_urls'],
      target: {
        namespace: 'android_app',
        package_name: 'com.cardiag.online',
        sha256_cert_fingerprints: fingerprints,
      },
    }]);
  });
  app.get('/sw.js', (_req, res) => sendPublicFile(res, 'sw.js'));
  app.get('/health', (_req, res) => res.json({ status: 'ok' }));

  // Render Cron (or another scheduler) triggers this endpoint once daily.
  // It is never public: a high-entropy CRON_SECRET is required in production.
  app.post('/api/internal/draft-maintenance', async (req, res) => {
    const expected = String(process.env.CRON_SECRET || '');
    const received = String(req.headers['x-cron-secret'] || '');
    const valid = expected.length >= 32 && received.length === expected.length
      && crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected));
    if (!valid) return res.status(401).json({ error: 'Tâche planifiée non autorisée.' });
    try {
      const result = await runDraftMaintenance({
        accountService,
        mailService: mailService || { sendDraftReminder: async () => ({ sent: false, reason: 'SMTP_NOT_CONFIGURED' }) },
        publicOrigin: canonicalOrigin,
      });
      return res.json(result);
    } catch (error) {
      console.error(`[${req.requestId}] Maintenance des brouillons échouée:`, error);
      return res.status(500).json({ error: 'Maintenance des brouillons indisponible.' });
    }
  });

  function route(validator, method) {
    return async (req, res) => {
      const error = validator(req.body);
      if (error) return res.status(400).json({ error });
      try {
        return res.json(await method(req.body));
      } catch (serviceError) {
        console.error(`[${req.requestId}] Service LLM indisponible:`, serviceError);
        if (serviceError?.code === 'LLM_NOT_CONFIGURED') {
          return res.status(503).json({ error: "Le service IA n'est pas configuré sur le serveur.", code: serviceError.code, requestId: req.requestId });
        }
        const upstreamStatus = Number(serviceError?.status || serviceError?.statusCode || 0);
        if (upstreamStatus === 401 || upstreamStatus === 403) {
          return res.status(503).json({ error: 'La clé Gemini est invalide ou ne peut pas utiliser ce modèle.', code: 'LLM_AUTH_ERROR', requestId: req.requestId });
        }
        if (upstreamStatus === 404) {
          return res.status(503).json({ error: 'Le modèle Gemini configuré est indisponible. Vérifiez GEMINI_MODEL.', code: 'LLM_MODEL_NOT_FOUND', requestId: req.requestId });
        }
        if (upstreamStatus === 429) {
          res.setHeader('Retry-After', serviceError?.headers?.get?.('retry-after') || '5');
          return res.status(429).json({ error: 'La limite Gemini est atteinte. Réessayez dans quelques instants.', code: 'LLM_RATE_LIMITED', requestId: req.requestId });
        }
        return res.status(500).json({ error: 'Le service IA est temporairement indisponible.', requestId: req.requestId });
      }
    };
  }

  const chatLimiter = createRateLimiter({ windowMs: 60_000, max: 12, accountService });
  const inlineLimiter = createRateLimiter({ windowMs: 60_000, max: 60, accountService });
  const sharedReportLimiter = createRateLimiter({ windowMs: 60_000, max: 30 });
  app.post('/api/chat', chatLimiter, route(validateChatBody, async ({ messages, carContext }) => llmService.chat(messages, carContext)));
  app.post('/api/inline', inlineLimiter, route(validateInlineBody, async ({ selectedText, carContext }) => ({ explanation: await llmService.inline(selectedText, carContext) })));
  app.get('/api/shared-reports/:id', sharedReportLimiter, async (req, res) => {
    if (!accountService) return res.status(503).json({ error: 'Partage indisponible.' });
    const id = String(req.params.id || '');
    if (!/^[a-zA-Z0-9_-]{20,80}$/.test(id)) return res.status(404).json({ error: 'Rapport introuvable.' });
    const shared = await accountService.getReportShare(id);
    if (!shared) return res.status(404).json({ error: 'Rapport introuvable ou expiré.' });
    res.setHeader('Cache-Control', 'private, no-store');
    return res.json(shared);
  });
  if (accountService) {
    app.use('/api', createGarageApiRouter(accountService));
    app.use('/api/admin', createGarageAdminRouter(accountService));
  } else {
    app.use('/api/garages', (_req, res) => res.status(503).json({ error:'Annuaire temporairement indisponible.', code:'GARAGE_DIRECTORY_UNAVAILABLE' }));
  }
  if (accountService) app.use('/api/account', createAccountRouter(accountService, { mailService, stripeService, publicOrigin: canonicalOrigin }));
  else app.use('/api/account', (_req, res) => res.status(503).json({ error: 'Firebase Admin non configuré.', code: 'AUTH_NOT_CONFIGURED' }));
  app.use((_req, res) => res.status(404).json({ error: 'Route introuvable.' }));
  app.use((error, req, res, _next) => {
    console.error(`[${req.requestId || 'unknown'}] Erreur non gérée:`, error);
    if (res.headersSent) return;
    res.status(500).json({ error: 'Erreur serveur temporaire.', requestId: req.requestId });
  });
  return app;
}
