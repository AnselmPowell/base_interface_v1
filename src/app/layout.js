'use client';

import { Suspense } from 'react';
import './styles/globals.css';
import Navigation from './components/Navigation.client';
import Footer from './components/Footer.client';
import { AuthProvider } from './contexts/AuthContext.client';

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <Suspense fallback={<div>Loading...</div>}>
            <Navigation />
               {children}
           <Footer/>
         </Suspense>
        </AuthProvider>
      </body>
    </html>
  );
}