import { Suspense } from 'react';
import { CredentialList } from './credential-list';

export default function CredentialsPage() {
  return (
    <Suspense fallback={<p className="text-sm">Loading...</p>}>
      <CredentialList />
    </Suspense>
  );
}
