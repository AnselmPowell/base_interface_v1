import { NextResponse } from 'next/server';
import executeQuery from '@/utils/db';

export async function GET() {
  try {
    const result = await executeQuery({
      query: 'SELECT id, first_name, last_name, email, created_at FROM api_user ORDER BY id DESC LIMIT 10'
    });
    return NextResponse.json(result.rows);
  } catch (error) {
    console.error("Error fetching users from database:", error);
    return NextResponse.json({ message: 'Failed to fetch users' }, { status: 500 });
  }
}

export async function POST(request) {
  try {
    const { first_name, last_name, email } = await request.json();
    
    // Validate input
    if (!first_name || !last_name || !email) {
      return NextResponse.json({ message: 'Missing required fields' }, { status: 400 });
    }

    const result = await executeQuery({
      query: `
        INSERT INTO api_user(first_name, last_name, email, created_at) 
        VALUES($1, $2, $3, CURRENT_TIMESTAMP) 
        RETURNING id, first_name, last_name, email, created_at
      `,
      values: [first_name, last_name, email],
    });

    // Format the created_at date to match Django's format
    const user = result.rows[0];
    user.created_at = new Date(user.created_at).toISOString();

    return NextResponse.json(user, { status: 201 });
  } catch (error) {
    console.error("Error creating user in database:", error);
    if (error.code === '23505') { // Unique violation error code
      return NextResponse.json({ message: 'Email already exists' }, { status: 400 });
    }
    return NextResponse.json({ message: 'Failed to create user' }, { status: 500 });
  }
}