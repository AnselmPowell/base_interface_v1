import { NextResponse } from 'next/server';
import executeQuery from '@/utils/db';

export async function GET() {
  try {
    const result = await executeQuery({
      query: 'SELECT * FROM users ORDER BY id DESC LIMIT 10'
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
    const result = await executeQuery({
      query: 'INSERT INTO users(first_name, last_name, email) VALUES($1, $2, $3) RETURNING *',
      values: [first_name, last_name, email],
    });
    return NextResponse.json(result.rows[0], { status: 201 });
  } catch (error) {
    console.error("Error creating user in database:", error);
    return NextResponse.json({ message: 'Failed to create user' }, { status: 500 });
  }
}