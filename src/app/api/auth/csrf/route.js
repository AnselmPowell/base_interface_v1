import { generateCSRFToken, setCSRFTokenCookie } from '@/app/auth';
import { cookies } from 'next/headers';

export async function GET() {
  const cookieStore = cookies();
  let csrfToken = cookieStore.get('csrfToken')?.value;

  if (!csrfToken) {
    csrfToken = generateCSRFToken();
    setCSRFTokenCookie(csrfToken);
  }

  return new Response(JSON.stringify({ csrfToken }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}