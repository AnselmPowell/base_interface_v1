import { PublicClientApplication, CryptoProvider } from '@azure/msal-node';

const msalConfig = {
    auth: {
        clientId: process.env.NEXT_PUBLIC_CLIENT_ID,
        authority: 'https://login.microsoftonline.com/consumers',
    },
};

export const msalInstance = new PublicClientApplication(msalConfig);


export async function getMicrosoftAuthUrl() {
  const cryptoProvider = new CryptoProvider();
  const { verifier, challenge } = await cryptoProvider.generatePkceCodes();

  const scopes = ['user.read', 'openid', 'profile', 'email'];
  const redirectUri = process.env.NEXT_PUBLIC_REDIRECT_URI;

  if (!redirectUri) {
    throw new Error('Redirect URI is not set in environment variables');
  }

  try {
    const authCodeUrlParameters = {
      scopes: scopes,
      redirectUri: redirectUri,
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
    };

    const response = await msalInstance.getAuthCodeUrl(authCodeUrlParameters);
    return { url: response, codeVerifier: verifier };
  } catch (error) {
    console.error("Error generating auth URL:", error);
    throw error;
  }
}