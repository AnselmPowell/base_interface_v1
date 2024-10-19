
import { Pool } from 'pg';

let pool;

function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.POSTGRES_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });

    // Error handling for the pool
    pool.on('error', (err) => {
      console.error('Unexpected error on idle client', err);
      process.exit(-1);
    });
  }
  return pool;
}

export default async function executeQuery({ query, values = [] }) {
  const pool = getPool();
  const client = await pool.connect();
  try {
    const result = await client.query(query, values);
    return { rows: result.rows, rowCount: result.rowCount };
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  } finally {
    client.release();
  }
}

export async function closePool() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}