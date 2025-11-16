require('dotenv').config();
const express = require('express');
const cors = require('cors');
const {poolPromise} = require('./controllers/userController');
const authRoutes = require('./routes/authRoutes');




const app = express();
const PORT = process.env.PORT || 3000;

// 🔧 Middleware
app.use(cors());
app.use(express.json());



// 🧪 Kiểm tra kết nối DB
app.get('/test-db', async (req, res) => {
    try {
        const pool = await poolPromise;
        const result = await pool.request().query('SELECT TOP 1 * FROM Users');
        res.json(result.recordset);
    } catch (err) {
        res.status(500).send('Database error: ' + err.message);
    }
});

app.use(express.json()); // xử lý JSON
app.use(express.urlencoded({ extended: true })); // xử lý form-urlencoded
// 🔐 Route xác thực người dùng
app.use('/api/auth', authRoutes);

// 🚀 Khởi động server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});