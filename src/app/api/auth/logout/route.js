import { logout } from '@/app/auth';

export async function POST(req) {
  return logout(req);
}