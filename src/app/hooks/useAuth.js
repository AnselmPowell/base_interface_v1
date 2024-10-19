'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';


export function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const res = await fetch('/api/auth/user', {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        if (data.message === 'No user logged in') {
          setUser(null);
        } else {
          setUser(data);
        }
      } else {
        setUser(null);
      }
    } catch (error) {
      console.error('Auth check failed', error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (credentials) => {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
        credentials: 'include' // This ensures cookies are sent with the request
      });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        router.push('/');
      } else {
        const errorData = await res.json();
        throw new Error(errorData.message || 'Login failed');
      }
    } catch (error) {
      console.error('Login error', error);
      throw error;
    }
  };

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', { 
        method: 'POST',
        credentials: 'include'
      });
      setUser(null);
      router.push('/login');
    } catch (error) {
      console.error('Logout error', error);
    }
  };


  const googleLogin = async (code) => {
    
    try {
      const response = await fetch(`/api/auth/google/callback?code=${code}`, {
      method: 'GET',
      credentials: 'include'
      });
      
      const data = await response.json();
      setUser(data.user);
      return data.user

    } catch (error) {
      console.error('Google login error', error);
      throw error;
    }
  };


  const microsoftLogin = async () => {
    try {
      const response = await fetch('/api/auth/microsoft/url');
      const { url } = await response.json();
      window.location.href = url;
    } catch (error) {
      console.error('Microsoft login error', error);
      throw error;
    }
  };
  
  // Include microsoftLogin in the return statement
  return { user, loading, login, logout, googleLogin, microsoftLogin, checkAuth };

}