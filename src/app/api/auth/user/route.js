export const dynamic = 'force-dynamic';

import { cookies } from 'next/headers';
import jwt from  'jsonwebtoken';
import * as authSchema from '@/database/schema/authSchema';

const JWT_SECRET = process.env.JWT_SECRET;

export async function GET() {
  const cookieStore = cookies();
  const refreshToken = cookieStore.get('refreshToken')?.value;

  if (!refreshToken) {
    return new Response(JSON.stringify({ message: 'No user logged in' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    const user = await authSchema.findUserById(decoded.userId);

    if (user) {
     
      return new Response(JSON.stringify(user), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    } else {
      throw new Error('User not found');
    }
  } catch (error) {
    console.error('Error getting current user:', error);
    return new Response(JSON.stringify({ message: 'No user logged in' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}