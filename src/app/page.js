import Head from 'next/head'
import styles from './styles/Home.module.css';
import UserList from './components/UserList.client';
import TestDBList from './components/TestDBList.client';

export default function HomePage() {
  return (
    <div className={styles.container}>
      <Head>
          <title>Base React Project</title>
          <meta name="description" content="A Next.js React application" />
          <link rel="icon" href="/favicon.ico" />
      </Head>
      <h1 className={styles.title}>Welcome to Base React Project!</h1>
      <p className={`${styles.description} text-lg mb-8 text-secondary`}>
        Get started by editing{' '}
        <code className={`${styles.code} bg-light rounded-sm p-2 font-mono text-xs text-primary`}>
          src/app/page.js
        </code>
        <br/>
      </p>
      <UserList />
      <TestDBList />
    </div>
  );
}