<<<<<<< HEAD
export const dynamic = 'force-dynamic';

=======
>>>>>>> b2f94e2d080bde926c0dfacf4f56429cb5754964
import { cookies } from 'next/headers';
import jwt from 'jsonwebtoken';
import { neon } from '@neondatabase/serverless';

const sql = neon(process.env.POSTGRES_URL);
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
    const [user] = await sql`
      SELECT id, username, first_name, last_name, email, is_staff, is_active, date_joined
      FROM auth_user 
      WHERE id = ${decoded.userId}
    `;
    if (user) {
      // Convert date_joined to ISO string format
      user.date_joined = new Date(user.date_joined).toISOString();
      
      return new Response(JSON.stringify(user), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    } else {
      throw new Error('User not found');
    }
  } catch (error) {
<<<<<<< HEAD
=======
    console.log(" AUTH USER Get user Fail--------------------------------------------------")
>>>>>>> b2f94e2d080bde926c0dfacf4f56429cb5754964
    console.error('Error getting current user:', error);
    return new Response(JSON.stringify({ message: 'No user logged in' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}