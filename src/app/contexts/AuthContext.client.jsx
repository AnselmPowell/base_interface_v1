'use client';
import React, { createContext, useContext, useState, useEffect } from 'react';
import { useAuth as useAuthHook } from '@/app/hooks/useAuth';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const auth = useAuthHook();


  return ( <AuthContext.Provider value={auth}>{children} </AuthContext.Provider>);
}

export const useAuth = () => useContext(AuthContext);