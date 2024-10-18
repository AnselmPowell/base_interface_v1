import { cookies } from 'next/headers';
import jwt from 'jsonwebtoken';
import { neon } from '@neondatabase/serverless';

const sql = neon(process.env.POSTGRES_URL);
const JWT_SECRET = process.env.JWT_SECRET;

export async function GET() {
  console.log(" AUTH USER --------------------------------------------------")
  const cookieStore = cookies();
  const refreshToken = cookieStore.get('refreshToken')?.value;
  console.log(" AUTH USER Cookies", cookieStore)
  console.log(" AUTH USER Refresh", refreshToken)
  console.log(" AUTH USER --------------------------------------------------")

  if (!refreshToken) {
    console.log(" AUTH USER  Fail --------------------------------------------------")
    return new Response(JSON.stringify({ message: 'No user logged in' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    console.log(" AUTH USER --------------------------------------------------")
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    const [user] = await sql`
      SELECT id, username, first_name, last_name, email, is_staff, is_active, date_joined
      FROM auth_user 
      WHERE id = ${decoded.userId}
    `;
    console.log(" AUTH USER User", user)
    if (user) {
      console.log(" AUTH USER Get user--------------------------------------------------")
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
    console.log(" AUTH USER Get user Fail--------------------------------------------------")
    console.error('Error getting current user:', error);
    return new Response(JSON.stringify({ message: 'No user logged in' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}