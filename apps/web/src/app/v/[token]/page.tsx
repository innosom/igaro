import type { Metadata } from 'next';
import { headers } from 'next/headers';
import process from 'node:process';
import {
  RESULT_VIEWS,
  UNAVAILABLE_VIEW,
  brandCss,
  buildProofRows,
  fetchVerification,
  formatDate,
  isPlausibleToken,
  isSafeSlug,
  visitorIp,
  warningText,
  type VerifyData,
} from '../../../lib/verify';

// Rendered on the server per request: the result is visible without JavaScript and never cached.
export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Credential verification',
  robots: { index: false, follow: false, nocache: true },
  referrer: 'no-referrer',
};

export default async function VerifyPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const h = await headers();
  const nonce = h.get('x-nonce') ?? undefined;
  const clientIp = visitorIp(h.get('x-forwarded-for'), process.env.WEB_TRUST_PROXY_HOPS);
  const outcome = await fetchVerification(token, { apiUrl: process.env.API_URL, clientIp });

  if (outcome.kind === 'unavailable') {
    return (
      <Shell nonce={nonce} css="">
        <Banner view={UNAVAILABLE_VIEW} role="alert" />
        <p className="mt-4 text-base text-slate-900">
          Reload this page to try again. If it keeps happening, contact the institution that issued the credential.
        </p>
      </Shell>
    );
  }

  const d = outcome.data;
  const view = RESULT_VIEWS[d.result];
  return (
    <Shell nonce={nonce} css={brandCss(d.institution)} institution={d.institution?.cardTitle ?? d.institution?.name}>
      <Banner view={view} role={d.result === 'VERIFIED' ? 'status' : 'alert'} />
      {d.result === 'SUPERSEDED' && d.supersededBy && (
        <p className="mt-4 text-lg font-semibold">
          <a className="text-blue-900 underline underline-offset-2" href={'/v/' + encodeURIComponent(d.supersededBy)}>
            View the replacement credential
          </a>
        </p>
      )}
      {warningText(d.warning) && (
        <p role="note" className="mt-4 rounded-md border-2 border-amber-900 bg-amber-100 p-3 text-base text-black">
          <strong>Warning: </strong>
          {warningText(d.warning)}
        </p>
      )}
      {view.showDetails && d.institution && d.holder && <Details d={d} token={token} />}
      {view.showDetails && d.proof && <ProofPanel d={d} />}
      {view.showDetails && d.institution && <Files d={d} token={token} />}
    </Shell>
  );
}

function Shell(props: { nonce?: string; css: string; institution?: string; children: React.ReactNode }) {
  return (
    <main className="brand mx-auto min-h-screen w-full max-w-xl px-4 pb-10">
      {props.css && <style nonce={props.nonce} dangerouslySetInnerHTML={{ __html: props.css }} />}
      <header className="brand-bar -mx-4 mb-4 border-b-4 px-4 py-3">
        <p className="text-sm font-semibold tracking-widest">{props.institution ?? 'iGARO credential check'}</p>
      </header>
      {props.children}
      <p className="mt-8 text-sm text-slate-700">
        Verify only at this iGARO address. A credential number printed on a card is never a way to look it up.
      </p>
    </main>
  );
}

function Banner({ view, role }: { view: { label: string; icon: string; summary: string; classes: string }; role: string }) {
  return (
    <section role={role} aria-labelledby="result-label" className={`rounded-lg border-4 p-5 text-center ${view.classes}`}>
      <p aria-hidden="true" className="text-5xl leading-none">
        {view.icon}
      </p>
      <h1 id="result-label" className="mt-2 text-3xl font-extrabold tracking-wide">
        {view.label}
      </h1>
      <p className="mt-2 text-lg">{view.summary}</p>
    </section>
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

function Details({ d, token }: { d: VerifyData; token: string }) {
  const h = d.holder!;
  const showPhoto = Boolean(h.photoUrl) && isPlausibleToken(token);
  return (
    <section aria-label="Credential details" className="mt-6 rounded-lg border border-slate-400 bg-white p-4">
      {showPhoto && (
        <img
          src={'/v/' + encodeURIComponent(token) + '/photo'}
          alt={'Photo of ' + h.fullName}
          width={120}
          height={150}
          className="mb-3 h-[150px] w-[120px] rounded-md border border-slate-400 object-cover"
        />
      )}
      <dl>
        <Row k="Holder" v={h.fullName} />
        <Row k="ID number" v={h.idNumber} />
        <Row k="Institution" v={d.institution!.name} />
        <Row k="Credential" v={d.type?.name || null} />
        <Row k="Status" v={d.status} />
        <Row k="Issued" v={formatDate(d.issuedAt)} />
        <Row k="Expires" v={formatDate(d.expiresAt) ?? (d.issuedAt ? 'No expiry' : null)} />
        {h.attributes.map(([k, v]) => (
          <Row key={k} k={k} v={v} />
        ))}
      </dl>
      <p className="mt-3 text-base font-semibold text-slate-950">Signed by {d.proof?.signedBy ?? d.institution!.name}</p>
    </section>
  );
}

function ProofPanel({ d }: { d: VerifyData }) {
  const rows = buildProofRows(d.proof);
  return (
    <section aria-labelledby="proof-h" className="mt-6 rounded-lg border border-slate-400 bg-white p-4">
      <h2 id="proof-h" className="text-lg font-bold text-slate-950">
        Proof
      </h2>
      <ul className="mt-2">
        {rows.map((r) => (
          <li key={r.id} className="border-b border-slate-300 py-2 last:border-0">
            <p className="text-base text-slate-950">
              <span aria-hidden="true">{r.ok ? '✓ ' : '– '}</span>
              <strong>{r.label}: </strong>
              {r.value}
            </p>
            {r.detail && <p className="break-all font-mono text-sm text-slate-800">{r.detail}</p>}
          </li>
        ))}
      </ul>
    </section>
  );
}

function Files({ d, token }: { d: VerifyData; token: string }) {
  const slug = d.institution?.slug ?? '';
  const keysPath = isSafeSlug(slug) ? '/i/' + slug + '/keys.json' : null;
  const link = 'font-medium text-blue-900 underline underline-offset-2';
  return (
    <section aria-labelledby="files-h" className="mt-6 rounded-lg border border-slate-400 bg-white p-4">
      <h2 id="files-h" className="text-lg font-bold text-slate-950">
        Check it yourself
      </h2>
      <ul className="mt-2 list-disc space-y-1 pl-5 text-base text-slate-950">
        <li>
          <a className={link} href={'/api/v1/verify/' + encodeURIComponent(token) + '/credential.json'} download="credential.json">
            Download the signed credential (credential.json)
          </a>
        </li>
        {keysPath && (
          <li>
            <a className={link} href={keysPath}>
              Institution public keys (keys.json)
            </a>
          </li>
        )}
      </ul>
      <p className="mt-3 text-sm text-slate-900">
        To verify offline with the open-source verifier, which makes no iGARO API calls, save both files and run:
      </p>
      <pre className="mt-1 overflow-x-auto rounded-md bg-slate-900 p-3 text-sm text-white">
        <code>igaro-verify credential.json --keys keys.json</code>
      </pre>
      <p className="mt-2 text-sm text-slate-900">
        Offline checking confirms the signature only. Suspension and revocation are shown on this page.
      </p>
    </section>
  );
}
