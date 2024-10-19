import { NextResponse } from 'next/server';
import fetchApi from '../fetchApi';

export async function GET() {
    try {
      const data = await fetchApi('users/');
      return NextResponse.json(data);
    } catch (error) {
      console.error("Error fetching users:", error);
      return NextResponse.json(
        { message: 'Failed to fetch users', error: error.message },
        { status: 500 }
      );
    }
}
  
export async function POST(request) {
    try {
      const body = await request.json();
      const data = await fetchApi('users/', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      return NextResponse.json(data, { status: 201 });
    } catch (error) {
      console.error("Error creating user:", error);
      return NextResponse.json(
        { message: 'Failed to create user' },
        { status: 500 }
      );
    }
  }