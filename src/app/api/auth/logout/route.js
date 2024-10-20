import { logout } from '@/auth/core/auth';

export async function POST(req) {
  return logout(req);
}