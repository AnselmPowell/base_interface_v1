import { register } from '@/app/auth';

export async function POST(req) {
  return register(req);
}