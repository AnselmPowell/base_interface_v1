'use client';

import { Suspense } from 'react';
import './styles/globals.css';
import Navbar from './components/main/Navbar.client';
import Footer from './components/main/Footer.client';
import { AuthProvider } from './contexts/AuthContext.client';

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <Suspense fallback={<div>Loading...</div>}>
            <Navbar />
               {children}
           <Footer/>
         </Suspense>
        </AuthProvider>
      </body>
    </html>
  );
}