import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { cookies } from 'next/headers';
import crypto from 'crypto';
import * as authSchema from '@/database/schema/authSchema';

const JWT_SECRET = process.env.JWT_SECRET;
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

const CSRF_SECRET = process.env.CSRF_SECRET;

export function generateCSRFToken() {
  const tokenValue = crypto.randomBytes(32).toString('hex');
  const timestamp = Date.now();
  const token = `${tokenValue}|${timestamp}`;
  const hash = crypto.createHmac('sha256', CSRF_SECRET).update(token).digest('hex');
  return `${token}|${hash}`;
}

export function validateCSRFToken(token, storedToken) {
  if (!token || !storedToken) {
    return false;
  }

  const [tokenValue, timestamp, hash] = token.split('|');

  if (token !== storedToken) {
    return false;
  }

  const expectedHash = crypto.createHmac('sha256', CSRF_SECRET).update(`${tokenValue}|${timestamp}`).digest('hex');
  const hashesMatch = crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(expectedHash));

  return hashesMatch;
}

export function setCSRFTokenCookie(token) {
  const cookieStore = cookies();
  cookieStore.set('csrfToken', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600, // 1 hour
    path: '/',
  });
}

const registerSchema = z.object({
  username: z.string().min(3).max(150),
  email: z.string().email(),
  password: z.string().min(8).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).*$/, 
    "Password must contain at least one uppercase letter, one lowercase letter, and one number"),
  first_name: z.string().max(150).optional(),
  last_name: z.string().max(150).optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
  csrfToken: z.string().optional(),
});

export async function register(req) {
  try {
    const { username, email, password, first_name = '', last_name = '', csrfToken } = registerSchema.parse(await req.json());

    if (!validateCSRFToken(csrfToken)) {
      return new Response(JSON.stringify({ message: 'Invalid CSRF token' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const existingUser = await authSchema.findUserByEmail(email);
    if (existingUser) {
      return new Response(JSON.stringify({ message: 'User already exists' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();

    const result = await authSchema.registerUser(username, email, hashedPassword, first_name, last_name, now);

    return new Response(JSON.stringify({ message: 'User registered successfully', user: result }), {
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
    const body = await req.json();
    const { email, password, csrfToken } = loginSchema.parse(body);

    const cookieStore = cookies();
    const storedToken = cookieStore.get('csrfToken')?.value;

    if (storedToken) {
      if (!validateCSRFToken(csrfToken, storedToken)) {
        return new Response(JSON.stringify({ message: 'Invalid CSRF token' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } else {
      const [tokenValue, timestamp, hash] = csrfToken.split('|');
      if (!tokenValue || !timestamp || !hash) {
        return new Response(JSON.stringify({ message: 'Invalid CSRF token format' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      setCSRFTokenCookie(csrfToken);
    }

    const user = await authSchema.findUserByEmail(email);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return new Response(JSON.stringify({ message: 'Invalid credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const accessToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

    const sessionKey = uuidv4();

    await authSchema.createSession(sessionKey, user.id, refreshToken, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));

    cookieStore.set('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60, // 7 days
      path: '/',
    });
    
    return new Response(JSON.stringify({ 
      accessToken, 
      user: { id: user.id, username: user.username, email: user.email } 
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
      await authSchema.deleteSession(decoded.userId);
      
      await authSchema.addToRevokedTokens(refreshToken, new Date(decoded.exp * 1000));
    } catch (error) {
      console.error('Error during logout:', error);
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

    const session = await authSchema.findSessionByUserId(userId);
    if (!session) {
      return new Response(JSON.stringify({ message: 'Invalid refresh token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const newAccessToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const newRefreshToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

    await authSchema.updateSession(
      session.session_key,
      userId,
      newRefreshToken,
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    );

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
    const user = await authSchema.findUserById(decoded.userId);

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
      const user = await authSchema.findUserById(decoded.userId);

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

export async function googleLoginRegister(email, name) {
  const [firstName, ...lastNameParts] = name.split(' ');
  const lastName = lastNameParts.join(' ');
  const username = email;
  const now = new Date().toISOString();
  const cookieStore = cookies();
  let csrfToken = cookieStore.get('csrfToken')?.value;
  if (!csrfToken) {
    csrfToken = generateCSRFToken();
    setCSRFTokenCookie(csrfToken);
  }
  const randomPassword = crypto.randomBytes(16).toString('hex');

  try {
    const user = await authSchema.findOrCreateGoogleUser(email, firstName, lastName, username, now, randomPassword);

    const accessToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

    const sessionKey = uuidv4();

    cookieStore.set('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60, // 7 days
      path: '/',
    });
    
    await authSchema.createSession(sessionKey, user.id, refreshToken, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));

    return new Response(JSON.stringify({ 
      accessToken, 
      user: { id: user.id, username: firstName, email: user.email, refreshToken: refreshToken } 
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Error in googleLoginRegister:', error);
    throw error;
  }
}

export async function microsoftLoginRegister(email, name) {
  const [firstName, ...lastNameParts] = name.split(' ');
  const lastName = lastNameParts.join(' ');
  const username = email;
  const now = new Date().toISOString();
  
  const randomPassword = crypto.randomBytes(16).toString('hex');

  try {
    const user = await authSchema.findOrCreateMicrosoftUser(email, firstName, lastName, username, now, randomPassword);

    const accessToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

    return { accessToken, user, refreshToken };
  } catch (error) {
    console.error('Error in microsoftLoginRegister:', error);
    throw error;
  }
}