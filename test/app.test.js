import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createApp } from '../src/app.js';

let server;
let baseUrl;

before(async () => {
  server = createApp({
    llmService: {
      chat: async () => ({ type: 'question', content: 'Question atelier ?' }),
      inline: async () => '<strong>P0301</strong> signale un raté.',
    },
  }).listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

test('health does not expose LLM runtime configuration', async () => {
  const response = await fetch(`${baseUrl}/health`);
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.status, 'ok');
  assert.equal(Object.hasOwn(body, 'llmConfigured'), false);
  assert.equal(Object.hasOwn(body, 'provider'), false);
  assert.equal(Object.hasOwn(body, 'model'), false);
});

test('the combined server serves the frontend without exposing environment files', async () => {
  const page = await fetch(`${baseUrl}/`);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Inspectez un véhicule d'occasion comme un expert/);
  assert.match(html, /rel="canonical" href="https:\/\/cardiag\.online\/"/);

  const [robots, sitemap, landingImage, demoReport] = await Promise.all([
    fetch(`${baseUrl}/robots.txt`), fetch(`${baseUrl}/sitemap.xml`),
    fetch(`${baseUrl}/assets/landing/cardiag-inspection.webp`),
    fetch(`${baseUrl}/assets/demo/rapport-expertise-demo-cardiag.pdf`),
  ]);
  assert.equal(robots.status, 200);
  assert.match(await robots.text(), /Sitemap: https:\/\/cardiag\.online\/sitemap\.xml/);
  assert.equal(sitemap.status, 200);
  assert.match(await sitemap.text(), /<loc>https:\/\/www\.cardiag\.online\/<\/loc>/);
  assert.equal(landingImage.status, 200);
  assert.match(landingImage.headers.get('content-type'), /image\/webp/);
  assert.equal(demoReport.status, 200);
  assert.match(demoReport.headers.get('content-type'), /application\/pdf/);

  const envFile = await fetch(`${baseUrl}/.env`);
  assert.equal(envFile.status, 404);
});

test('alternate browser hosts redirect to the canonical CarDiag domain without redirecting API calls', async () => {
  const alternateHost = 'fiche-expert-auto.onrender.com';
  const page = await fetch(`${baseUrl}/?niveau=complet&profil=acheteur`, {
    redirect: 'manual',
    // Render forwards the original public host through this header.
    headers: { Accept: 'text/html', 'X-Forwarded-Host': alternateHost },
  });
  assert.equal(page.status, 308);
  assert.equal(page.headers.get('location'), 'https://www.cardiag.online/?niveau=complet&profil=acheteur');

  const api = await fetch(`${baseUrl}/health`, {
    redirect: 'manual',
    headers: { Accept: 'application/json', 'X-Forwarded-Host': alternateHost },
  });
  assert.equal(api.status, 200);
  assert.equal((await api.json()).status, 'ok');
});

test('Firebase authentication helper configuration stays available', async () => {
  const response = await fetch(`${baseUrl}/`);
  // Firebase's popup/redirect resolver loads the GAPI iframe bridge dynamically.
  // A working /__/auth/iframe alone is insufficient if this script is blocked.
  const directives = new Map(response.headers.get('content-security-policy')
    .split(';').map(part => part.trim().split(/\s+/)).map(([name, ...sources]) => [name, sources]));
  assert.ok(directives.get('script-src').includes('https://apis.google.com'));
  assert.ok(directives.get('script-src').includes('https://www.gstatic.com'));
  assert.ok(!directives.get('script-src').includes('*'));
  assert.match(
    response.headers.get('content-security-policy'),
    /frame-src 'self' https:\/\/cardiag-f1ea7\.firebaseapp\.com https:\/\/accounts\.google\.com/,
  );

  const init = await fetch(`${baseUrl}/__/firebase/init.json`);
  assert.equal(init.status, 200);
  assert.equal(init.headers.get('cache-control'), 'no-store');
  assert.match(await init.text(), /"authDomain": "www\.cardiag\.online"/);

  const source = await import('node:fs/promises').then(({ readFile }) => readFile(new URL('../src/app.js', import.meta.url), 'utf8'));
  assert.match(source, /res\.removeHeader\('X-Frame-Options'\)/);
  assert.match(source, /res\.removeHeader\('Content-Security-Policy'\)/);
});

test('app routes survive refreshes and legacy local fiche links redirect safely', async () => {
  const appPage = await fetch(`${baseUrl}/app/inspection/t123/controle/moteur`);
  assert.equal(appPage.status, 200);
  assert.match(await appPage.text(), /id="appRoot"|id="wizardHeader"/);

  const legacy = await fetch(`${baseUrl}/fiche/t123`, { redirect: 'manual' });
  assert.equal(legacy.status, 308);
  assert.equal(legacy.headers.get('location'), '/app/inspection/t123/rapport');
});

test('CORS allows the web and native production frontends', async () => {
  for (const origin of ['https://cardiag.online', 'https://localhost']) {
    const response = await fetch(`${baseUrl}/api/chat`, {
      method: 'OPTIONS',
      headers: {
        Origin: origin,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
      },
    });

    assert.equal(response.status, 204);
    assert.equal(response.headers.get('access-control-allow-origin'), origin);
    assert.match(response.headers.get('access-control-allow-methods'), /POST/);
  }
});

test('chat and inline routes call the configured service', async () => {
  const payload = { carContext: { marque: 'Renault', modele: 'Clio IV', motorisation: '1.5 dCi' } };
  const chat = await fetch(`${baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...payload, messages: [{ role: 'user', content: 'Bruit moteur' }] }),
  });
  const inline = await fetch(`${baseUrl}/api/inline`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...payload, selectedText: 'P0301' }),
  });
  assert.deepEqual(await chat.json(), { type: 'question', content: 'Question atelier ?' });
  assert.match((await inline.json()).explanation, /P0301/);
});

test('a Gemini authentication failure returns a useful configuration error', async () => {
  const authServer = createApp({
    llmService: {
      chat: async () => {
        const error = new Error('forbidden');
        error.status = 403;
        throw error;
      },
      inline: async () => '',
    },
  }).listen(0);
  await new Promise((resolve) => authServer.once('listening', resolve));

  const response = await fetch(`http://127.0.0.1:${authServer.address().port}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messages: [{ role: 'user', content: 'Bruit moteur' }],
      carContext: { marque: 'Renault', modele: 'Clio IV', motorisation: '1.5 dCi' },
    }),
  });

  assert.equal(response.status, 503);
  assert.equal((await response.json()).code, 'LLM_AUTH_ERROR');
  await new Promise((resolve) => authServer.close(resolve));
});
