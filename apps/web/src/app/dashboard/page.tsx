import type { Metadata } from 'next';
import { DashboardStub } from './stub';

export const metadata: Metadata = { title: 'Dashboard' };

export default function DashboardPage() {
  return <DashboardStub />;
}
