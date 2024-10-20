import { getGoogleAuthUrl } from '@/auth/social/googleAuth';

export async function GET() {
  const url = getGoogleAuthUrl();
  return new Response(JSON.stringify({ url }), {
    headers: { 'Content-Type': 'application/json' },
  });
}



