'use client';
import Link from 'next/link';
import { useRouter } from 'next/navigation'
import styles from '../styles/Home.module.css';

export default function Navigation() {
  const router = useRouter();
  return (
    <nav className={styles.nav}>
      <Link href="/pages/login">Login</Link>
      <Link href="/">Home</Link>
      <Link href="/pages/about">About</Link>
    </nav>
  );
}