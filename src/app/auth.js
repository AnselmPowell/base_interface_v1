import { neon } from '@neondatabase/serverless';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { cookies } from 'next/headers';


import crypto from 'crypto';


const sql = neon(process.env.POSTGRES_URL);

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

// The server validates this token before processing the request, adding an extra layer of security to your application.
// Provides defense against CSRF attacks:
export function validateCSRFToken(token, storedToken) {

  if (!token || !storedToken) {
    return false;
  }

  const [tokenValue, timestamp, hash] = token.split('|');

  // Instead of checking the age, we'll just ensure the tokens match
  if (token !== storedToken) {
    return false;
  }

  // Verify the hash
  const expectedHash = crypto.createHmac('sha256', CSRF_SECRET).update(`${tokenValue}|${timestamp}`).digest('hex');
  const hashesMatch = crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(expectedHash));

  return hashesMatch;
}


// set the CSRT Token 
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
      // If there's no stored token, this might be a first-time login or a login after a long time
      const [tokenValue, timestamp, hash] = csrfToken.split('|');
      if (!tokenValue || !timestamp || !hash) {
        return new Response(JSON.stringify({ message: 'Invalid CSRF token format' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      // Set the provided token as the new stored token
      setCSRFTokenCookie(csrfToken);
    }
    

    const [user] = await sql`SELECT * FROM auth_user WHERE LOWER(email) = LOWER(${email})`;

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
      await sql`DELETE FROM django_session WHERE session_data LIKE ${'%"userId":' + decoded.userId + '%'}`;
      
      // Add the token to the blacklist
      await sql`INSERT INTO revoked_tokens (token, expiry) VALUES (${refreshToken}, ${new Date(decoded.exp * 1000)})`;
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

    const [session] = await sql`SELECT * FROM django_session WHERE session_data LIKE ${'%"userId":' + userId + '%'}`;
    if (!session) {
      return new Response(JSON.stringify({ message: 'Invalid refresh token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const newAccessToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const newRefreshToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

      // Update the session with the new refresh token
      await sql`UPDATE django_session 
                SET session_data = ${JSON.stringify({userId, refreshToken: newRefreshToken})}, 
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



// Google Authenication ##################################################################



export async function googleLoginRegister(email, name) {
  const [firstName, ...lastNameParts] = name.split(' ');
  const lastName = lastNameParts.join(' ');
  const username = email; // Use email as username for Google-authenticated users
  const now = new Date().toISOString();
  const cookieStore = cookies();
  let csrfToken = cookieStore.get('csrfToken')?.value;
  if (!csrfToken) {
    csrfToken = generateCSRFToken();
    setCSRFTokenCookie(csrfToken);
  }
  // Generate a random, unusable password
  const randomPassword = crypto.randomBytes(16).toString('hex');

  try {
    const [user] = await sql`
      INSERT INTO auth_user (
        username, 
        email, 
        first_name, 
        last_name, 
        is_active, 
        date_joined, 
        password,
        last_login,
        is_superuser,
        is_staff
      )
      VALUES (
        ${username}, 
        ${email}, 
        ${firstName}, 
        ${lastName}, 
        true, 
        ${now}, 
        ${randomPassword},
        ${null},
        false,
        false
      )
      ON CONFLICT (username) DO UPDATE SET
        email = EXCLUDED.email,
        first_name = EXCLUDED.first_name,
        last_name = EXCLUDED.last_name,
        is_active = true
      RETURNING id, username, email, first_name, last_name, is_active
    `;


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
    
    await sql`INSERT INTO django_session (session_key, session_data, expire_date) 
    VALUES (${sessionKey}, ${JSON.stringify({userId: user.id, refreshToken})}, ${new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)})`;

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
    const [user] = await sql`
      INSERT INTO auth_user (
        username, 
        email, 
        first_name, 
        last_name, 
        is_active, 
        date_joined, 
        password,
        last_login,
        is_superuser,
        is_staff
      )
      VALUES (
        ${username}, 
        ${email}, 
        ${firstName}, 
        ${lastName}, 
        true, 
        ${now}, 
        ${randomPassword},
        ${null},
        false,
        false
      )
      ON CONFLICT (username) DO UPDATE SET
        email = EXCLUDED.email,
        first_name = EXCLUDED.first_name,
        last_name = EXCLUDED.last_name,
        is_active = true
      RETURNING id, username, email, first_name, last_name, is_active
    `;

    const accessToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

    return { accessToken, user, refreshToken };
  } catch (error) {
    console.error('Error in microsoftLoginRegister:', error);
    throw error;
  }
}