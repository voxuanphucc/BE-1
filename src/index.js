require('dotenv').config();
const express = require('express');
const { poolPromise } = require('./config/db');

const app = express();
const PORT = 3000;

app.get('/test-db', async (req, res) => {
    try {
        const pool = await poolPromise;
        const result = await pool.request().query('SELECT TOP 1 * FROM Users');
        res.json(result.recordset);
    } catch (err) {
        res.status(500).send('Database error: ' + err.message);
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});