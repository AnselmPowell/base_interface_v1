import { cookies } from 'next/headers';
import {DJANGO_API_ENDPOINT, DJANGO_API_ENDPOINT_LOCAL} from "@/utils/config/defaults" 

const DJANGO_API_URL = DJANGO_API_ENDPOINT || DJANGO_API_ENDPOINT_LOCAL


export default async function fetchApi(endpoint, options = {}) {
  const cookieStore = cookies();
  const token = cookieStore.get('token');

  const headers = {
    'Content-Type': 'application/json',
    ...(token && { 'Authorization': `Bearer ${token.value}` }),
    ...options.headers
  };

  try {
    const response = await fetch(`${DJANGO_API_URL}${endpoint}`, {
      ...options,
      headers,
      credentials: 'include',
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    // Set or update token if it's in the response
    if (data.token) {
      cookies().set('token', data.token, { 
        httpOnly: true, 
        secure: process.env.NODE_ENV === 'production'
      });
    }

    return data;
  } catch (error) {
    console.error("Fetch error:", error);
    throw error;  
  }
}