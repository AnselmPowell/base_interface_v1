import { cookies } from 'next/headers';
import Login from './Login.client';

export default function LoginPage() {
  const cookieStore = cookies();
  const token = cookieStore.get('token');

  return <Login initialToken={token?.value} />;
}