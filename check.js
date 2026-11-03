// Robot de surveillance des notes (GitHub Actions + Playwright).
// Se connecte au portail via Microsoft, lit le tableau, l'envoie au web app Google.
// Les identifiants viennent des « secrets » GitHub, jamais du code.

const { chromium } = require('playwright');
const crypto = require('crypto');
const fs = require('fs');

const {
  UM5_EMAIL, UM5_PASSWORD, UM5_TOTP_SECRET, RESULTS_URL, WEBAPP_URL, WEBAPP_TOKEN
} = process.env;
const TEST_MODE = process.env.TEST_MODE === 'true';
const INDEX_URL = 'https://etu.um5.ac.ma/index.php?:nav=resultat_elp::index';

// ---------- Code à usage unique (TOTP, RFC 6238) : uniquement si la double authentification est activée ----------
function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of str.replace(/[\s=]/g, '').toUpperCase()) {
    const v = alphabet.indexOf(c);
    if (v < 0) throw new Error('SECRET_TOTP_INVALIDE');
    bits += v.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function totp(secret, nowMs = Date.now(), digits = 6) {
  const counter = Math.floor(nowMs / 30000);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  const code = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % Math.pow(10, digits);
  return String(code).padStart(digits, '0');
}

// ---------- Connexion Microsoft ----------
async function loginMicrosoft(page) {
  const vis = sel => page.locator(sel).first().isVisible().catch(() => false);

  await page.waitForURL(/login\.microsoftonline\.com/, { timeout: 30000 });
  await page.locator('input[name="loginfmt"]').fill(UM5_EMAIL);
  await page.locator('#idSIButton9').click();

  await page.locator('input[name="passwd"]').waitFor({ state: 'visible', timeout: 30000 });
  await page.locator('input[name="passwd"]').fill(UM5_PASSWORD);
  await page.waitForTimeout(500);
  await page.locator('#idSIButton9').click();

  let totpTries = 0;
  for (let i = 0; i < 40; i++) {
    if (/^https:\/\/etu\.um5\.ac\.ma/.test(page.url())) return;

    if (await vis('#passwordError, #usernameError')) throw new Error('IDENTIFIANTS_REFUSES');

    if (await vis('input[name="otc"]')) {
      if (!UM5_TOTP_SECRET) throw new Error('MFA_REQUIRED');
      if (totpTries++ >= 2) throw new Error('CODE_TOTP_REFUSE');
      await page.locator('input[name="otc"]').fill(totp(UM5_TOTP_SECRET));
      await page.locator('#idSubmit_SAOTCC_Continue').click();
    } else if (await vis('#KmsiCheckboxField, #KmsiDescription')) {
      await page.locator('#idSIButton9').click();               // « Rester connecté ? » -> Oui
    } else if (await vis('#idDiv_SAOTCAS_Title, #idDiv_SAOTCS_Proofs, [data-value="PhoneAppNotification"]')) {
      throw new Error('MFA_REQUIRED');                           // validation sur téléphone : impossible à automatiser
    }
    await page.waitForTimeout(1500);
  }
  throw new Error('CONNEXION_TIMEOUT');
}

// ---------- Lecture du tableau ----------
async function readTable(page) {
  const sel = 'main table, table';
  try {
    await page.waitForSelector(sel, { timeout: 15000 });
    const html = await page.$eval(sel, t => t.outerHTML);
    if (html.indexOf('Session 1') !== -1) return html;
  } catch (e) { /* pas de tableau sur cette page */ }
  return null;
}

async function getResultsHtml(page) {
  await page.goto(RESULTS_URL, { waitUntil: 'domcontentloaded' });

  // Le portail peut afficher sa propre page de connexion avant Microsoft
  if (/^https:\/\/etu\.um5\.ac\.ma/.test(page.url()) && !(await page.locator('table').count())) {
    const lien = page.locator('a[href*="oauth2"]:not([href*="disconnect"])').first();
    if (await lien.count()) await lien.click();
  }

  if (/login\.microsoftonline\.com/.test(page.url())) {
    await loginMicrosoft(page);
    await page.goto(RESULTS_URL, { waitUntil: 'domcontentloaded' });
  } else if (!(await page.locator('table').count())) {
    throw new Error('PAGE_CONNEXION_INCONNUE');
  }

  let html = await readTable(page);
  if (html) return html;

  // Repli : passer par la page de sélection, comme dans le navigateur
  await page.goto(INDEX_URL, { waitUntil: 'domcontentloaded' });
  const lien = page.locator('a[href*="resultat_elp::list"]').first();
  if (await lien.count()) {
    await lien.click();
    html = await readTable(page);
    if (html) return html;
  }
  throw new Error('TABLEAU_INTROUVABLE');
}

// ---------- Envoi au web app Google ----------
async function post(payload) {
  const res = await fetch(WEBAPP_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain;charset=utf-8' },
    body: JSON.stringify(Object.assign({ token: WEBAPP_TOKEN }, payload)),
    redirect: 'follow'
  });
  const text = await res.text();
  try { return JSON.parse(text); } catch (e) { return { ok: false, erreur: 'REPONSE_INATTENDUE_HTTP_' + res.status }; }
}

(async () => {
  for (const k of ['UM5_EMAIL', 'UM5_PASSWORD', 'RESULTS_URL', 'WEBAPP_URL', 'WEBAPP_TOKEN']) {
    if (!process.env[k]) { console.error('Secret manquant : ' + k); process.exit(2); }
  }
  fs.mkdirSync('debug', { recursive: true });

  const browser = await chromium.launch();
  const context = await browser.newContext({
    locale: 'fr-FR',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
  });
  const page = await context.newPage();
  let code = 0;

  try {
    const html = await getResultsHtml(page);
    const res = await post({ test: TEST_MODE, html });
    console.log('Réponse du web app :', JSON.stringify(res));
    if (!res.ok) throw new Error(res.erreur || 'ENVOI_ECHEC');
  } catch (e) {
    code = 1;
    console.error('ÉCHEC :', e.message);
    try {
      await page.screenshot({ path: 'debug/page.png', fullPage: true });
      fs.writeFileSync('debug/page.html', await page.content());
      fs.writeFileSync('debug/url.txt', page.url().split('?')[0]);
    } catch (err) { /* capture impossible */ }
    // Signale l'erreur par email (une seule fois tant que le problème dure)
    if (!/^(CODE_SECRET_INVALIDE|JSON_INVALIDE|REPONSE_INATTENDUE)/.test(e.message)) {
      try { await post({ erreur: e.message }); } catch (err) { console.error('Alerte non envoyée'); }
    }
  }

  await browser.close();
  process.exit(code);
})();

module.exports = { totp };
