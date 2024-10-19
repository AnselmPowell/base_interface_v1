'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '@/app/contexts/AuthContext.client';
import { FcGoogle } from 'react-icons/fc'; // Import Google icon
<<<<<<< HEAD
import { TfiMicrosoftAlt } from "react-icons/tfi";
=======
>>>>>>> b2f94e2d080bde926c0dfacf4f56429cb5754964

export default function LoginForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [csrfToken, setCsrfToken] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const router = useRouter();
  const searchParams = useSearchParams();
  const { googleLogin, login, checkAuth } = useAuth();
<<<<<<< HEAD
  const [isLoading, setIsLoading] = useState(false);
=======
>>>>>>> b2f94e2d080bde926c0dfacf4f56429cb5754964

  useEffect(() => {
    fetch('/api/auth/csrf')
      .then(res => res.json())
      .then(data => setCsrfToken(data.csrfToken))
      .catch(err => console.error("Failed to fetch CSRF token", err));

    const justRegistered = searchParams.get('registered');
    if (justRegistered === 'true') {
      setError('Registration successful! Please log in with your new account.');
    }
  }, [searchParams]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      await login({ email: email.toLowerCase(), password, csrfToken });
      router.push('/');
      checkAuth();
    } catch (err) {
      setError(err.message || 'Failed to login. Please check your credentials and try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleGoogleLogin = async () => {
    try {
      const response = await fetch('/api/auth/google/url');
      const { url } = await response.json();
      router.push(url);
    } catch (error) {
      console.error('Failed to get Google Auth URL', error);
    }
  };

  const handleMicrosoftLogin = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/auth/microsoft/url');
      const { url, codeVerifier } = await response.json();


      window.location.href = url;
    } catch (error) {
      console.error('Failed to get Microsoft Auth URL', error);
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">Sign in to your account</h2>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-4 shadow-2xl sm:rounded-lg sm:px-10">
          {error && (
            <div className={`mb-4 ${error.includes('successful') ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'} border px-4 py-3 rounded-md relative`} role="alert">
              <span className="block sm:inline">{error}</span>
            </div>
          )}
          <form className="space-y-6" onSubmit={handleSubmit}>
            <input type="hidden" name="csrfToken" value={csrfToken} />
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">Email address</label>
              <div className="mt-1">
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">Password</label>
              <div className="mt-1">
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isSubmitting}
                className={`w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition duration-150 ease-in-out ${isSubmitting ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                {isSubmitting ? 'Signing in...' : 'Sign in'}
              </button>
            </div>
          </form>

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-gray-500">Or continue with</span>
              </div>
            </div>

            <div className="mt-6">
              <button
                onClick={handleGoogleLogin}
                className="w-full flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition duration-150 ease-in-out"
<<<<<<< HEAD
                >
                <FcGoogle className="h-5 w-5 mr-2" />
                Sign in with Google
                {isLoading ? 'Loading...' : 'Sign in with Google'}
              </button>
            </div>
            <div className="mt-6">
            <button
              onClick={handleMicrosoftLogin}
              disabled={isLoading}
              className="w-full flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition duration-150 ease-in-out"
              >
              <TfiMicrosoftAlt className="h-5 w-5 mr-2"  />
              {isLoading ? 'Loading...' : 'Sign in with Microsoft'}
            </button>

            </div>
            
=======
              >
                <FcGoogle className="h-5 w-5 mr-2" />
                Sign in with Google
              </button>
            </div>
>>>>>>> b2f94e2d080bde926c0dfacf4f56429cb5754964
          </div>

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-gray-500">Don&apos;t have an account?</span>
              </div>
            </div>
            <div className="mt-6">
              <Link href="/register" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-indigo-600 bg-white hover:bg-gray-50 transition duration-150 ease-in-out">
                Register
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}