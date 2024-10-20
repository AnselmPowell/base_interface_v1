import sql from '../db';

export const registerUser = async (username, email, hashedPassword, firstName, lastName, now) => {
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
      ${firstName},
      ${lastName},
      ${email},
      ${false},
      ${true},
      ${now}
    ) RETURNING id, username, email
  `;
  return result[0];
};

export const findUserByEmail = async (email) => {
  const [user] = await sql`SELECT * FROM auth_user WHERE LOWER(email) = LOWER(${email})`;
  return user;
};

export const createSession = async (sessionKey, userId, refreshToken, expireDate) => {
  await sql`INSERT INTO django_session (session_key, session_data, expire_date) 
    VALUES (${sessionKey}, ${JSON.stringify({userId, refreshToken})}, ${expireDate})`;
};

export const deleteSession = async (userId) => {
  await sql`DELETE FROM django_session WHERE session_data LIKE ${'%"userId":' + userId + '%'}`;
};

export const addToRevokedTokens = async (refreshToken, expiry) => {
  await sql`INSERT INTO revoked_tokens (token, expiry) VALUES (${refreshToken}, ${expiry})`;
};

export const findSessionByUserId = async (userId) => {
  const [session] = await sql`SELECT * FROM django_session WHERE session_data LIKE ${'%"userId":' + userId + '%'}`;
  return session;
};

export const updateSession = async (sessionKey, userId, newRefreshToken, newExpireDate) => {
  await sql`UPDATE django_session 
            SET session_data = ${JSON.stringify({userId, refreshToken: newRefreshToken})}, 
                expire_date = ${newExpireDate}
            WHERE session_key = ${sessionKey}`;
};

export const findUserById = async (userId) => {
  const [user] = await sql`SELECT id, username FROM auth_user WHERE id = ${userId}`;
  return user;
};

export const findOrCreateGoogleUser = async (email, firstName, lastName, username, now, randomPassword) => {
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
  return user;
};

export const findOrCreateMicrosoftUser = async (email, firstName, lastName, username, now, randomPassword) => {
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
  return user;
};