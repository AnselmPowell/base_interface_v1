export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import { getMicrosoftAuthUrl } from '@/app/microsoftAuth';
import { cookies } from 'next/headers';

export async function GET() {
    
    try {
        const { url, codeVerifier } = await getMicrosoftAuthUrl();

        // Set the code verifier as a cookie
        const cookieStore = cookies();
        cookieStore.set('codeVerifier', codeVerifier, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 600, // 10 minutes
            path: '/',
        });
        

        return NextResponse.json({ url, codeVerifier});
    } catch (error) {
        console.error("Error generating Microsoft auth URL:", error);
        return NextResponse.json({ error: 'Failed to generate auth URL' }, { status: 500 });
    }
}