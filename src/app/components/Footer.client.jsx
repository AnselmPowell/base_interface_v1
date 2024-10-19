'use client';

import styles from '../styles/Home.module.css'
import { useState, useEffect } from 'react';


export default function Footer() {
    
  return (
    <footer className={styles.footer}>
            <a
                href="https://nextjs.org"
                target="_blank"
                rel="noopener noreferrer"
            >
                Powered by Next.js
            </a>
        </footer>
  );
}
