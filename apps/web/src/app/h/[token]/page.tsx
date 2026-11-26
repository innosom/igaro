import type { Metadata } from 'next';
import { headers } from 'next/headers';
import process from 'node:process';
import {
  credentialFileHref,
  fetchHolder,
  holderCardHref,
  statusText,
  type HolderData,
} from '../../../lib/holder';
import { brandCss, formatDate, isSafeSlug, visitorIp } from '../../../lib/verify';

// Private holder page (ADR 0023, 0031, 0032). The token in the URL is the holder's only credential:
// server-rendered per request, never cached, never indexed, no Referer, and never written to a log here.
export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Your credential',
  robots: { index: false, follow: false, nocache: true },
  referrer: 'no-referrer',
};

const link = 'font-medium text-blue-900 underline underline-offset-2';
const button =
  'inline-block rounded-md border-2 border-black bg-white px-4 py-3 text-base font-semibold text-black underline-offset-2 hover:underline focus-visible:outline focus-visible:outline-4 focus-visible:outline-offset-2 focus-visible:outline-blue-900';

export default async function HolderPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const h = await headers();
  const nonce = h.get('x-nonce') ?? undefined;
  const clientIp = visitorIp(h.get('x-forwarded-for'), process.env.WEB_TRUST_PROXY_HOPS);
  const outcome = await fetchHolder(token, { apiUrl: process.env.API_URL, clientIp });

  if (outcome.kind === 'not_found') {
    return (
      <Shell nonce={nonce} css="">
        <section role="alert" className="rounded-lg border-4 border-slate-950 bg-slate-700 p-5 text-center text-white">
          <h1 className="text-2xl font-extrabold">LINK NOT FOUND</h1>
          <p className="mt-2 text-lg">
            This link is not valid. Open the original message from your institution and use the link in it again.
          </p>
        </section>
      </Shell>
    );
  }
  if (outcome.kind === 'unavailable') {
    return (
      <Shell nonce={nonce} css="">
        <section role="alert" className="rounded-lg border-4 border-slate-950 bg-slate-200 p-5 text-center text-black">
          <h1 className="text-2xl font-extrabold">TEMPORARILY UNAVAILABLE</h1>
          <p className="mt-2 text-lg">We could not load your credential. Reload this page in a moment.</p>
        </section>
      </Shell>
    );
  }

  const d = outcome.data;
  return (
    <Shell nonce={nonce} css={brandCss(d.institution)} institution={d.institution.cardTitle ?? d.institution.name}>
      <Credential d={d} token={token} />
    </Shell>
  );
}

function Shell(props: { nonce?: string; css: string; institution?: string; children: React.ReactNode }) {
  return (
    <main className="brand mx-auto min-h-screen w-full max-w-xl px-4 pb-10">
      {props.css && <style nonce={props.nonce} dangerouslySetInnerHTML={{ __html: props.css }} />}
      <header className="brand-bar -mx-4 mb-4 border-b-4 px-4 py-3">
        <p className="text-sm font-semibold tracking-widest">{props.institution ?? 'iGARO credential'}</p>
      </header>
      {props.children}
      <p className="mt-8 text-sm text-slate-700">
        This page is private to you. Anyone with this link can see and download your card, so do not share it. To let
        others check your credential, share its verification page instead.
      </p>
    </main>
  );
}

function Row({ k, v }: { k: string; v: string | null }) {
  if (!v) return null;
  return (
    <div className="flex flex-col border-b border-slate-300 py-2 sm:flex-row sm:gap-4">
      <dt className="text-sm font-semibold text-slate-700 sm:w-40">{k}</dt>
      <dd className="break-words text-base text-slate-950">{v}</dd>
    </div>
  );
}

function Credential({ d, token }: { d: HolderData; token: string }) {
  const c = d.credential;
  const st = statusText(c.status);
  const png = c.hasCardPng ? holderCardHref(token, 'png') : null;
  const pdf = c.hasCardPdf ? holderCardHref(token, 'pdf') : null;
  const file = credentialFileHref(c.verificationToken);
  const keysPath = isSafeSlug(d.institution.slug) ? '/i/' + d.institution.slug + '/keys.json' : null;
  const verifyPath = '/v/' + encodeURIComponent(c.verificationToken);
  return (
    <>
      <section aria-labelledby="holder-h" className="rounded-lg border border-slate-400 bg-white p-4">
        <h1 id="holder-h" className="text-2xl font-extrabold text-slate-950">
          {d.holderName}
        </h1>
        <dl className="mt-2">
          <Row k="Institution" v={d.institution.name} />
          <Row k="Credential" v={c.type.name || null} />
          <Row k="Status" v={st.label} />
          <Row k="Issued" v={formatDate(c.issuedAt)} />
          <Row k="Expires" v={formatDate(c.expiresAt) ?? (c.issuedAt ? 'No expiry' : null)} />
        </dl>
        <p role="note" className="mt-3 text-base text-slate-950">
          {st.note}
        </p>
      </section>

      <section aria-labelledby="dl-h" className="mt-6 rounded-lg border border-slate-400 bg-white p-4">
        <h2 id="dl-h" className="text-lg font-bold text-slate-950">
          Downloads
        </h2>
        {png || pdf ? (
          <ul className="mt-3 flex flex-wrap gap-3">
            {png && (
              <li>
                <a className={button} href={png} download="credential-card.png">
                  Download card (PNG image)
                </a>
              </li>
            )}
            {pdf && (
              <li>
                <a className={button} href={pdf} download="credential-card.pdf">
                  Download card (PDF)
                </a>
              </li>
            )}
          </ul>
        ) : (
          <p className="mt-2 text-base text-slate-950">
            {c.status === 'ACTIVE'
              ? 'Your card is not ready yet. Reload this page in a minute.'
              : 'The card can be downloaded only while the credential is active.'}
          </p>
        )}
        {file && (
          <p className="mt-4 text-base text-slate-950">
            <a className={link} href={file} download="credential.json">
              Download the signed credential (credential.json)
            </a>
          </p>
        )}
        {keysPath && (
          <p className="mt-2 text-base text-slate-950">
            <a className={link} href={keysPath}>
              Institution public keys (keys.json)
            </a>
          </p>
        )}
      </section>

      <section aria-labelledby="share-h" className="mt-6 rounded-lg border border-slate-400 bg-white p-4">
        <h2 id="share-h" className="text-lg font-bold text-slate-950">
          Share and verify
        </h2>
        <p className="mt-2 text-base text-slate-950">
          <a className={link} href={verifyPath}>
            Open the public verification page
          </a>
        </p>
      </section></>
  );
}
