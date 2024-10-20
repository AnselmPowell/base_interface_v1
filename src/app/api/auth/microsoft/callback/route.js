export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import { msalInstance } from '@/auth/social/microsoftAuth';
import { microsoftLoginRegister } from '@/auth/core/auth';
import { cookies } from 'next/headers';

export async function GET(request) {
    const { searchParams } = new URL(request.url);
    const code = searchParams.get('code');

    if (!code) {
        return NextResponse.json({ error: 'No code provided' }, { status: 400 });
    }

    try {
        const cookieStore = cookies();
        const codeVerifier = cookieStore.get('codeVerifier')?.value;

        if (!codeVerifier) {
            console.error('No code verifier found in cookies');
            return NextResponse.json({ error: 'Authentication failed', details: 'No code verifier found' }, { status: 400 });
        }

        const tokenRequest = {
            code,
            scopes: ["user.read", "openid", "profile", "email"],
            redirectUri: process.env.NEXT_PUBLIC_MICROSOFT_REDIRECT_URI,
            codeVerifier: codeVerifier,
        };

        const response = await msalInstance.acquireTokenByCode(tokenRequest);
        const { account } = response;

        const email = account.username || account.idTokenClaims.email;
        const name = account.name || `${account.given_name} ${account.family_name}`.trim();

        const { accessToken, user, refreshToken } = await microsoftLoginRegister(email, name);
        
        cookieStore.set('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60,
            path: '/',
        });

        cookieStore.delete('codeVerifier');

        return NextResponse.redirect(new URL(process.env.NEXT_PUBLIC_REDIRECT_URL, request.url));
    } catch (error) {
        console.error('Microsoft authentication error:', error);
        return NextResponse.json({ error: 'Authentication failed', details: error.message }, { status: 500 });
    }
}