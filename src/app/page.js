import styles from './styles/Home.module.css'
import Head from 'next/head'
import UserList from './components/UserList.client';

export default function Home() {
  return (
  <div className={styles.container}>
      <Head>
          <title>Base React Project</title>
          <meta name="description" content="A Next.js React application" />
          <link rel="icon" href="/favicon.ico" />
      </Head>

      <main className={styles.main}>
          <h1 className={styles.title}>
              Welcome to Base React Project!
          </h1>
          <br/>
          <p className={styles.description}>
              Get started by editing{' '}
              <code className={styles.code}>src/app/page.js</code>
          </p>
          <br/>
          <UserList/>
      </main>
     
  </div>
  )
}