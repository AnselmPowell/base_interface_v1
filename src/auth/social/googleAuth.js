import { OAuth2Client } from 'google-auth-library';

const oauth2Client = new OAuth2Client(
  process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.NEXT_PUBLIC_GOOGLE_REDIRECT_URI
);

export function getGoogleAuthUrl() {
  const scopes = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
  ];

  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    include_granted_scopes: true,
  });
}

export async function getGoogleUser(code) {
  const { tokens } = await oauth2Client.getToken(code);
  oauth2Client.setCredentials(tokens);

  const userinfo = await oauth2Client.request({
    url: 'https://www.googleapis.com/oauth2/v3/userinfo',
  });

  return userinfo.data;
}