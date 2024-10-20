'use client';

import Link from 'next/link';
import { useAuth } from '@/app/contexts/AuthContext.client'

export default function Navbar() {
  const { user, loading, logout } = useAuth();

  console.log("In the Navigation Test User Information:", user)

  if (loading) {
    return <nav className="p-4 bg-white-800 text-white">Loading...</nav>;
  }


  return (
    <nav className="p-4 bg-white-800 text-white flex justify-between items-center">
      <div>
        <Link href="/" className="text-lg text-black font-semibold hover:text-blue-300">Logo</Link>
      </div>
      <div className="space-x-4">
        {user ? (
          <>
            <span className="font-medium">Welcome, {user.username}!</span>
            <button 
              onClick={logout} 
              className="bg-white-500 hover:bg-gray-600 text-black px-3 py-1 rounded-md"
            >
              Logout
            </button>
          </>
        ) : (
          <>
            <Link 
              href="/login" 
              className="bg-gray-500 hover:bg-gray-600 text-white px-3 py-1 rounded-md"
            >
              Login
            </Link>
            <Link 
              href="/register" 
              className="bg-gray-500 hover:bg-gray-600 text-white px-3 py-1 rounded-md"
            >
              Register
            </Link>
          </>
        )}
      </div>
    </nav>
  );
}