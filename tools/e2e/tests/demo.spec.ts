// iGARO end-to-end demo script (white paper v1.0 section 15, docs/acceptance/W5.md item 7).
// One ordered story against a running stack. Read tools/e2e/README.md for the required environment.
// Every generated value (slug, emails, password) is unique per run, so the script can be repeated on the same database.
//
// Steps: create institution -> invite -> accept + login -> branding -> credential type -> holder + photo -> issue ->
// open the QR URL (VERIFIED) -> holder email + private page -> suspend (SUSPENDED) -> reinstate (VERIFIED) -> revoke
// (REVOKED, reinstate impossible) -> reissue (old SUPERSEDED with link) -> CSV+ZIP import with one email per holder ->
// audit chain -> optional database tamper checks (needs E2E_DATABASE_URL, a superuser).
import { randomBytes } from 'node:crypto';
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import pg from 'pg';
import { jpeg, png, zip } from './fixtures.js';
import { firstMessageText, waitForMessages } from './mailpit.js';

const need = (name: string): string => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required (see tools/e2e/README.md)`);
  return v;
};

const baseURL = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:3000';
const dbUrl = process.env.E2E_DATABASE_URL;
const importRows = Number(process.env.E2E_IMPORT_ROWS ?? '25');
const run = randomBytes(4).toString('hex');
const s = {
  instName: `E2E University ${run}`,
  slug: `e2e-${run}`,
  adminEmail: `admin-${run}@e2e.test`,
  adminPassword: `E2e-${randomBytes(12).toString('base64url')}`,
  holderName: `Ada Demo ${run}`,
  holderExt: `ada-${run}`,
  holderEmail: `holder-${run}@e2e.test`,
  typeCode: `STUDENT_${run.toUpperCase()}`,
  typeName: `Student ID ${run}`,
  cardTitle: `E2E Card ${run}`,
  cred1: { id: '', token: '' },
  cred2: { id: '', token: '' },
  cred2New: { id: '', token: '' },
};

const heading = (page: Page, text: string) => page.getByRole('heading', { name: text, exact: true });
const tokenFromUrl = (url: string): string => new URL(url, baseURL).pathname.split('/').filter(Boolean).pop()!;
const idFromUrl = tokenFromUrl;

async function login(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard/);
}

test.describe.serial('iGARO demo script (white paper section 15)', () => {
  let platform: BrowserContext;
  let admin: BrowserContext;
  let anon: BrowserContext; // what a person scanning the QR code is: no session
  let platformPage: Page;
  let adminPage: Page;
  let anonPage: Page;

  test.beforeAll(async ({ browser }) => {
    platform = await browser.newContext({ baseURL });
    admin = await browser.newContext({ baseURL });
    anon = await browser.newContext({ baseURL });
    platformPage = await platform.newPage();
    adminPage = await admin.newPage();
    anonPage = await anon.newPage();
  });
  test.afterAll(async () => {
    await Promise.all([platform?.close(), admin?.close(), anon?.close()]);
  });

  const expectVerify = async (token: string, label: string) => {
    await anonPage.goto(`/v/${token}`);
    await expect(heading(anonPage, label)).toBeVisible();
  };

  test('1. platform admin creates an institution and invites its admin', async () => {
    await login(platformPage, need('E2E_PLATFORM_EMAIL'), need('E2E_PLATFORM_PASSWORD'));
    await platformPage.goto('/dashboard/platform');
    await platformPage.getByRole('button', { name: 'New institution' }).click();
    await platformPage.getByLabel('Name', { exact: true }).fill(s.instName);
    await platformPage.getByLabel('Slug').fill(s.slug);
    await platformPage.getByLabel('First admin email').fill(s.adminEmail);
    await platformPage.getByRole('button', { name: 'Create and invite' }).click();
    await expect(platformPage.getByRole('status')).toContainText('An invite was sent');
    await expect(platformPage.getByRole('row', { name: new RegExp(s.slug) })).toBeVisible();
  });

  test('2. the institution admin accepts the invite from the email and logs in', async () => {
    const text = await firstMessageText(`to:"${s.adminEmail}"`);
    const link = /\/invite\/accept#token=([A-Za-z0-9_-]+)/.exec(text);
    expect(link, 'the invite email carries an accept link').not.toBeNull();
    await adminPage.goto(`/invite/accept#token=${link![1]}`);
    await adminPage.getByLabel('Your name (optional)').fill('Demo Admin');
    await adminPage.getByLabel('New password').fill(s.adminPassword);
    await adminPage.getByLabel('Confirm password').fill(s.adminPassword);
    await adminPage.getByRole('button', { name: 'Set password' }).click();
    await expect(adminPage.getByText('Your password is set.')).toBeVisible();
    // The link works once.
    await adminPage.goto('about:blank'); // a hash-only change would not reload the page
    await adminPage.goto(`/invite/accept#token=${link![1]}`);
    await adminPage.getByLabel('New password').fill(s.adminPassword);
    await adminPage.getByLabel('Confirm password').fill(s.adminPassword);
    await adminPage.getByRole('button', { name: 'Set password' }).click();
    await expect(adminPage.getByRole('alert')).toBeVisible();

    await login(adminPage, s.adminEmail, s.adminPassword);
    await expect(adminPage.getByText(s.instName).first()).toBeVisible();
  });

  test('3. branding: logo, card title, colours', async () => {
    await adminPage.goto('/dashboard/branding');
    await adminPage.locator('#logo').setInputFiles({ name: 'logo.png', mimeType: 'image/png', buffer: png(40) });
    await expect(adminPage.getByText('Logo saved.')).toBeVisible();
    await adminPage.getByLabel('Card title').fill(s.cardTitle);
    await adminPage.getByLabel('Primary colour').fill('#1a4d8f');
    await adminPage.getByLabel('Secondary colour').fill('#f0f4f8');
    await adminPage.getByRole('button', { name: 'Save branding' }).click();
    await expect(adminPage.getByText('Branding saved.')).toBeVisible();
  });

  test('4. credential type, holder and photo', async () => {
    await adminPage.goto('/dashboard/types');
    await adminPage.getByRole('button', { name: 'New type' }).click();
    await adminPage.getByLabel('Code', { exact: true }).fill(s.typeCode);
    await adminPage.getByLabel('Name', { exact: true }).fill(s.typeName);
    await adminPage.getByLabel('Default validity in days (optional)').fill('365');
    await adminPage.getByLabel('Key', { exact: true }).fill('program');
    await adminPage.getByLabel('Label', { exact: true }).fill('Programme');
    await adminPage.getByLabel('Required').check();
    await adminPage.getByRole('button', { name: 'Create type' }).click();
    await expect(adminPage.getByRole('row', { name: new RegExp(s.typeCode) })).toBeVisible();

    await adminPage.goto('/dashboard/holders');
    await adminPage.getByRole('button', { name: 'New holder' }).click();
    await adminPage.getByLabel('Full name').fill(s.holderName);
    await adminPage.getByLabel('External ID (optional)').fill(s.holderExt);
    await adminPage.getByLabel('Email (optional)').fill(s.holderEmail);
    await adminPage.getByRole('button', { name: 'Save' }).click();
    const row = adminPage.getByRole('row', { name: new RegExp(s.holderExt) });
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: 'Edit' }).click();
    await adminPage.locator('#photo').setInputFiles({ name: 'photo.png', mimeType: 'image/png', buffer: png(90) });
    await expect(adminPage.getByText(`Photo saved for ${s.holderName}.`)).toBeVisible();
  });

  async function issue(program: string): Promise<{ id: string; token: string; holderLink: string }> {
    await adminPage.goto('/dashboard/credentials/new');
    await adminPage.locator('#holder').selectOption({ label: `${s.holderName} (${s.holderExt})` });
    await adminPage.locator('#type').selectOption(s.typeCode);
    await adminPage.getByLabel('Programme (required)').fill(program);
    await adminPage.getByRole('button', { name: 'Issue credential' }).click();
    await expect(heading(adminPage, 'Credential issued')).toBeVisible();
    const verifyHref = (await adminPage.locator('a[href^="/v/"]').getAttribute('href'))!;
    const holderHref = (await adminPage.locator('a[href^="/h/"]').getAttribute('href'))!;
    await adminPage.getByRole('link', { name: 'Open credential' }).click();
    await expect(adminPage).toHaveURL(/\/dashboard\/credentials\/[0-9a-f-]{36}$/);
    return { id: idFromUrl(adminPage.url()), token: tokenFromUrl(verifyHref), holderLink: holderHref };
  }

  test('5. issue a credential; the QR URL shows VERIFIED, signed by the institution, with the institution branding', async () => {
    const c = await issue('Computer Science');
    s.cred1 = { id: c.id, token: c.token };
    expect(c.token).toMatch(/^[A-Za-z0-9_-]{22}$/); // 128-bit token, the only thing in the QR/URL
    await expectVerify(c.token, 'VERIFIED');
    await expect(anonPage.getByText(s.holderName).first()).toBeVisible();
    await expect(anonPage.getByText(/Signed by/).first()).toBeVisible();
    await expect(heading(anonPage, 'Proof')).toBeVisible();
    await expect(anonPage.getByText(s.cardTitle).first()).toBeVisible();
    // The public page never reveals the internal id.
    expect(await anonPage.content()).not.toContain(c.id);
  });

  test('6. the holder gets an email with a private link; the holder page works', async () => {
    const text = await firstMessageText(`to:"${s.holderEmail}"`);
    const m = /\/h\/([A-Za-z0-9_-]{22})/.exec(text);
    expect(m, 'the holder email carries a /h/:token link').not.toBeNull();
    await anonPage.goto(`/h/${m![1]}`);
    await expect(heading(anonPage, s.holderName)).toBeVisible();
    await expect(anonPage.getByRole('link', { name: 'Download the signed credential (credential.json)' })).toBeVisible();
    // The worker renders the card after issuance; reload until the PNG link appears, then download it and check the file type.
    const cardLink = anonPage.getByRole('link', { name: 'Download card (PNG image)' });
    await expect(async () => {
      await anonPage.reload();
      await expect(cardLink).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 90_000, intervals: [2_000] });
    const card = await anon.request.get(new URL((await cardLink.getAttribute('href'))!, baseURL).toString());
    expect(card.status()).toBe(200);
    expect((await card.body()).subarray(0, 8).toString('hex')).toBe('89504e470d0a1a0a');
    // A guessed holder link reveals nothing.
    await anonPage.goto(`/h/${randomBytes(16).toString('base64url')}`);
    await expect(heading(anonPage, 'LINK NOT FOUND')).toBeVisible();
  });

  test('7. suspend -> SUSPENDED, reinstate -> VERIFIED', async () => {
    await adminPage.goto(`/dashboard/credentials/${s.cred1.id}`);
    await adminPage.getByRole('button', { name: 'Suspend', exact: true }).click();
    // A reason is mandatory and recorded.
    await adminPage.getByRole('button', { name: 'Confirm suspend' }).click();
    await expect(adminPage.locator('#reason-error')).toBeVisible();
    await adminPage.getByLabel('Reason (required, recorded in the audit log)').fill('E2E demo: documents under review');
    await adminPage.getByRole('button', { name: 'Confirm suspend' }).click();
    await expect(adminPage.getByText('Credential suspended.')).toBeVisible();
    await expectVerify(s.cred1.token, 'SUSPENDED');

    await adminPage.getByRole('button', { name: 'Reinstate', exact: true }).click();
    await adminPage.getByRole('button', { name: 'Confirm reinstate' }).click();
    await expect(adminPage.getByText('Credential reinstated.')).toBeVisible();
    await expectVerify(s.cred1.token, 'VERIFIED');
  });

  test('8. revoke -> REVOKED; reinstating a revoked credential is impossible', async () => {
    await adminPage.goto(`/dashboard/credentials/${s.cred1.id}`);
    await adminPage.getByRole('button', { name: 'Revoke', exact: true }).click();
    await adminPage.getByLabel('Reason (required, recorded in the audit log)').fill('E2E demo: issued in error');
    await adminPage.getByRole('button', { name: 'Confirm revoke' }).click();
    // Revoking is final and needs an explicit confirmation.
    await expect(adminPage.getByText('Confirm that revoking is final.')).toBeVisible();
    await adminPage.getByLabel('I understand this is final and cannot be undone.').check();
    await adminPage.getByRole('button', { name: 'Confirm revoke' }).click();
    await expect(adminPage.getByText('Credential revoked.')).toBeVisible();
    await expectVerify(s.cred1.token, 'REVOKED');

    // The dashboard offers no way back ...
    await adminPage.goto(`/dashboard/credentials/${s.cred1.id}`);
    await expect(adminPage.getByRole('button', { name: 'Suspend', exact: true })).toHaveCount(0);
    await expect(adminPage.getByRole('button', { name: 'Reinstate', exact: true })).toHaveCount(0);
    // ... and the API refuses a forged request from the same session.
    const me = await (await admin.request.get('/api/v1/auth/me')).json();
    const res = await admin.request.post(`/api/v1/credentials/${s.cred1.id}/reinstate`, {
      headers: { 'x-csrf-token': me.csrfToken, 'content-type': 'application/json' },
      data: {},
    });
    expect(res.status()).toBeGreaterThanOrEqual(400);
    expect(res.status()).toBeLessThan(500);
    await expectVerify(s.cred1.token, 'REVOKED');
  });

  test('9. reissue -> the old credential is SUPERSEDED with a link to the new VERIFIED one', async () => {
    const c = await issue('Physics');
    s.cred2 = { id: c.id, token: c.token };
    await expectVerify(c.token, 'VERIFIED');

    await adminPage.goto(`/dashboard/credentials/${c.id}`);
    await adminPage.getByRole('button', { name: 'Reissue', exact: true }).click();
    await adminPage.getByLabel('Reason (required, recorded in the audit log)').fill('E2E demo: programme corrected');
    await adminPage.getByLabel('Programme (required)').fill('Applied Physics');
    await adminPage.getByRole('button', { name: 'Confirm reissue' }).click();
    await expect(adminPage).toHaveURL(/\/dashboard\/credentials\/[0-9a-f-]{36}$/);
    await expect(adminPage).not.toHaveURL(new RegExp(c.id));
    s.cred2New.id = idFromUrl(adminPage.url());

    await expectVerify(c.token, 'SUPERSEDED');
    await anonPage.getByRole('link', { name: 'View the replacement credential' }).click();
    await expect(heading(anonPage, 'VERIFIED')).toBeVisible();
    s.cred2New.token = tokenFromUrl(anonPage.url());
    expect(s.cred2New.token).not.toBe(c.token);
    await expect(anonPage.getByText('Applied Physics').first()).toBeVisible();
  });

  test('10. CSV + photo ZIP import: preview, run, one email per holder', async () => {
    test.setTimeout(10 * 60_000);
    const n = importRows;
    const ids = Array.from({ length: n }, (_, i) => `imp-${run}-${String(i).padStart(4, '0')}`);
    const header = 'fullName,externalId,email,credentialType,program,expiresAt';
    const csv = [header, ...ids.map((id, i) => `Import Person ${i} ${run},${id},${id}@import.e2e.test,${s.typeCode},Programme ${i % 7},`)].join('\n') + '\n';
    await adminPage.goto('/dashboard/import');
    await adminPage.locator('#import-csv').setInputFiles({ name: 'people.csv', mimeType: 'text/csv', buffer: Buffer.from(csv) });
    await adminPage.locator('#import-zip').setInputFiles({ name: 'photos.zip', mimeType: 'application/zip', buffer: zip(ids.map((id) => ({ name: `${id}.jpg`, data: jpeg() }))) });
    await adminPage.getByRole('button', { name: 'Check file' }).click();
    await expect(adminPage.getByText(`Starting the import issues ${n} credentials.`)).toBeVisible();
    await adminPage.getByRole('button', { name: 'Start import' }).click();
    await expect(adminPage.getByText('Import finished. All credentials were issued.')).toBeVisible({ timeout: 8 * 60_000 });

    // One email per imported holder, each with a distinct private link (plus the single holder from step 6 for this institution).
    const mails = await waitForMessages(`subject:"from ${s.instName}"`, n, 8 * 60_000);
    expect(mails.messages_count).toBeGreaterThanOrEqual(n);
    const first = await waitForMessages(`to:"${ids[0]}@import.e2e.test"`);
    expect(first.messages_count).toBe(1);
  });

  test('11. the audit log chain verifies', async () => {
    await adminPage.goto('/dashboard/audit');
    await adminPage.getByRole('button', { name: 'Verify chain' }).click();
    await expect(adminPage.getByText(/Chain intact/)).toBeVisible();
  });

  test.describe('database tamper checks (need E2E_DATABASE_URL, a superuser connection)', () => {
    test.skip(!dbUrl, 'E2E_DATABASE_URL is not set');
    let client: pg.Client;
    test.beforeAll(async () => {
      client = new pg.Client({ connectionString: dbUrl });
      await client.connect();
    });
    test.afterAll(async () => {
      await client?.end();
    });

    /** Run SQL with triggers disabled for this transaction (superuser only), as an attacker with database access would. */
    const bypass = async (sql: string, params: unknown[]) => {
      await client.query('BEGIN');
      try {
        await client.query('SET LOCAL session_replication_role = replica');
        await client.query(sql, params);
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      }
    };

    test('12. editing a signed field directly in the database -> VERIFICATION FAILED (and restoring it -> VERIFIED)', async () => {
      const id = s.cred2New.id;
      const original = (await client.query('SELECT payload FROM credentials WHERE id = $1', [id])).rows[0]?.payload;
      expect(original, 'credential exists').toBeTruthy();
      await expectVerify(s.cred2New.token, 'VERIFIED');
      try {
        await bypass(`UPDATE credentials SET payload = jsonb_set(payload, '{holder,fullName}', '"Mallory Tamper"') WHERE id = $1`, [id]);
        await expectVerify(s.cred2New.token, 'VERIFICATION FAILED');
        await expect(anonPage.getByText('Mallory Tamper')).toHaveCount(0); // a failed check shows no credential details
      } finally {
        await bypass('UPDATE credentials SET payload = $2::jsonb WHERE id = $1', [id, JSON.stringify(original)]);
      }
      await expectVerify(s.cred2New.token, 'VERIFIED');
    });

    test('13. a revoked credential cannot be changed back in the database; verification still shows REVOKED', async () => {
      // No bypass here: the trigger must refuse an ordinary UPDATE, even from the owner role.
      await expect(client.query(`UPDATE credentials SET status = 'ACTIVE' WHERE id = $1`, [s.cred1.id])).rejects.toThrow();
      await expectVerify(s.cred1.token, 'REVOKED');
    });
  });
});
