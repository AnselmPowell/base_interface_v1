// 

'use client';
import Head from 'next/head'
import styles from './styles/Home.module.css';
import UserList from './components/UserList.client';
import TestDBList from './components/TestDBList.client';
import { useAuth } from '@/app/contexts/AuthContext.client';

export default function HomePage() {
  const { user, checkAuth } = useAuth();
  setTimeout(() => {
    // checkAuth()
    // console.log("PAGE REFRESH!", user)
  }, 3000);

  return (
    <div className={styles.container}>
      <Head>
          <title>Base React Project</title>
          <meta name="description" content="A Next.js React application" />
          <link rel="icon" href="/favicon.ico" />
      </Head>
      <h1 className={styles.title}>Base React Project!</h1>
      {user && <p className={`${styles.description} text-lg mb-8 text-secondary`}>
        Welcome{' '}
        <code className={`${styles.code} bg-light rounded-sm p-2 font-mono text-xs text-primary`}>
        {user.username}!
        </code>
        <br/>
      </p>}
      <UserList />
      <TestDBList />
    </div>
  );
}