import type { Metadata } from 'next';
import { AcceptInviteForm } from './accept-form';

export const metadata: Metadata = {
  title: 'Accept invitation',
  robots: { index: false, follow: false },
  referrer: 'no-referrer',
};

export default function AcceptInvitePage() {
  return <AcceptInviteForm />;
}
