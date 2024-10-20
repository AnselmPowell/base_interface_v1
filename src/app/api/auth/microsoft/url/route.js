export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import { getMicrosoftAuthUrl } from '@/auth/social/microsoftAuth';
import { cookies } from 'next/headers';

export async function GET() {
    console.log("Initiating Microsoft auth URL generation");
    
    try {
        const { url, codeVerifier } = await getMicrosoftAuthUrl();

        const cookieStore = cookies();
        cookieStore.set('codeVerifier', codeVerifier, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 600,
            path: '/',
        });

        return NextResponse.json({ url, codeVerifier });
    } catch (error) {
        console.error("Error generating Microsoft auth URL:", error);
        return NextResponse.json({ error: 'Failed to generate auth URL' }, { status: 500 });
    }
}
