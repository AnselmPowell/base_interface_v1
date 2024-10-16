import { neon } from '@neondatabase/serverless';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { cookies } from 'next/headers';

const sql = neon(process.env.POSTGRES_URL);

const JWT_SECRET = process.env.JWT_SECRET;
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

const registerSchema = z.object({
  username: z.string().min(3).max(150),
  email: z.string().email(),
  password: z.string().min(8).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).*$/, 
    "Password must contain at least one uppercase letter, one lowercase letter, and one number"),
  first_name: z.string().max(150).optional(),
  last_name: z.string().max(150).optional(),
});

const loginSchema = z.object({
  username: z.string(),
  password: z.string(),
});

export async function register(req) {
  try {
    const { username, email, password, first_name = '', last_name = '' } = registerSchema.parse(await req.json());

    const existingUser = await sql`SELECT * FROM auth_user WHERE username = ${username} OR email = ${email}`;
    if (existingUser.length > 0) {
      return new Response(JSON.stringify({ message: 'User already exists' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();

    const result = await sql`
      INSERT INTO auth_user (
        password, 
        last_login, 
        is_superuser, 
        username, 
        first_name, 
        last_name, 
        email, 
        is_staff, 
        is_active, 
        date_joined
      ) VALUES (
        ${hashedPassword},
        ${null},
        ${false},
        ${username},
        ${first_name},
        ${last_name},
        ${email},
        ${false},
        ${true},
        ${now}
      ) RETURNING id, username, email
    `;

    return new Response(JSON.stringify({ message: 'User registered successfully', user: result[0] }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({ message: 'Validation failed', errors: error.errors }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ message: 'Registration failed', error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

export async function login(req) {
  try {
    const { username, password } = loginSchema.parse(await req.json());

    const [user] = await sql`SELECT * FROM auth_user WHERE username = ${username}`;

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return new Response(JSON.stringify({ message: 'Invalid credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const accessToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

    const sessionKey = uuidv4();
    await sql`INSERT INTO django_session (session_key, session_data, expire_date) 
              VALUES (${sessionKey}, ${JSON.stringify({userId: user.id, refreshToken})}, ${new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)})`;

    const cookieStore = cookies();
    cookieStore.set('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60, // 7 days
      path: '/',
    });

    return new Response(JSON.stringify({ 
      accessToken, 
      user: { id: user.id, username: user.username } 
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Login error:', error);
    return new Response(JSON.stringify({ message: 'Login failed', error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

export async function logout(req) {
  const cookieStore = cookies();
  const refreshToken = cookieStore.get('refreshToken')?.value;

  if (refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, JWT_SECRET);
      await sql`DELETE FROM django_session WHERE session_data LIKE ${'%"userId":' + decoded.userId + '%'}`;
    } catch (error) {
      console.error('Error deleting session:', error);
    }
  }

  cookieStore.delete('refreshToken');

  return new Response(JSON.stringify({ message: 'Logged out successfully' }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

export async function refreshToken(req) {
  const cookieStore = cookies();
  const refreshToken = cookieStore.get('refreshToken')?.value;

  if (!refreshToken) {
    return new Response(JSON.stringify({ message: 'Refresh token not found' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    const userId = decoded.userId;

    const [session] = await sql`SELECT * FROM django_session WHERE session_data LIKE ${'%"userId":' + userId + '%'}`;
    if (!session) {
      return new Response(JSON.stringify({ message: 'Invalid refresh token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const newAccessToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const newRefreshToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

    const newSessionKey = uuidv4();
    await sql`UPDATE django_session 
              SET session_key = ${newSessionKey}, 
                  session_data = ${JSON.stringify({userId, refreshToken: newRefreshToken})}, 
                  expire_date = ${new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)}
              WHERE session_key = ${session.session_key}`;

    cookieStore.set('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60, // 7 days
      path: '/',
    });

    return new Response(JSON.stringify({ accessToken: newAccessToken }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    return new Response(JSON.stringify({ message: 'Invalid refresh token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}


export async function getCurrentUser() {
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
    const [user] = await sql`SELECT id, username FROM auth_user WHERE id = ${decoded.userId}`;

    if (user) {
      return new Response(JSON.stringify({ id: user.id, username: user.username }), {
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



export function withAuth(handler) {
  return async (req) => {
    const cookieStore = cookies();
    const refreshToken = cookieStore.get('refreshToken')?.value;

    if (!refreshToken) {
      return new Response(JSON.stringify({ message: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    try {
      const decoded = jwt.verify(refreshToken, JWT_SECRET);
      const [user] = await sql`SELECT id, username FROM auth_user WHERE id = ${decoded.userId}`;

      if (user) {
        return handler(req, user);
      } else {
        throw new Error('User not found');
      }
    } catch (error) {
      console.error('Auth error:', error);
      return new Response(JSON.stringify({ message: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  };
}