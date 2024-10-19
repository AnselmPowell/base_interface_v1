import { refreshToken } from '@/app/auth';

export async function POST(req) {
  return refreshToken(req);
}