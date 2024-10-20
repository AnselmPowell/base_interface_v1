import { register } from '@/auth/core/auth';

export async function POST(req) {
  return register(req);
}