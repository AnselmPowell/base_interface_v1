import { login } from '@/app/auth';

export async function POST(req) {
  return login(req);
}
