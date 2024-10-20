import { refreshToken } from '@/auth/core/auth';

export async function POST(req) {
  return refreshToken(req);
}