import { login } from '@/auth/core/auth';

export async function POST(req) {
  return login(req);
}
