const sql = require('mssql');
const { poolPromise } = require('../config/db');

exports.getProfile = async (req, res) => {
    try {
        const pool = await poolPromise;
        const result = await pool.request()
            .input('id', sql.Int, parseInt(req.user.id))
            .query('SELECT UserID AS Id, Email, FullName FROM Users WHERE UserID = @id');

        const user = result.recordset[0];
        if (!user) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });
        }

        res.status(200).json({ success: true, user });
    } catch (err) {
        console.error('Lỗi lấy profile:', err.message);
        console.error('Stack trace:', err.stack);
        console.error('User ID:', req.user?.id);
        res.status(500).json({ success: false, message: 'lỗi máy chủ', error: err.message });
    }
};