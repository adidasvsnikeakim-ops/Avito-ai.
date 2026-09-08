import 'dotenv/config';
import pg from 'pg';
import fs from 'fs';

const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const sql = fs.readFileSync('../db/schema.sql', 'utf8');
await pool.query(sql);

console.log('Database schema initialized.');
await pool.end();
