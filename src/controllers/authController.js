const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { poolPromise } = require('../config/db');
const { sendResetEmail } = require('../utils/mailer');




exports.register = async (req, res) => {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
        return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
    }

    try {
        const pool = await poolPromise;

        // Kiểm tra trùng email hoặc số điện thoại
        const checkUser = await pool.request()
            .input('email', email)

            .query('SELECT * FROM Users WHERE Email = @email');

        if (checkUser.recordset.length > 0) {
            return res.status(409).json({ success: false, message: 'Email đã được sử dụng' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.request()
            .input('fullName', fullName)
            .input('email', email)

            .input('passwordHash', hashedPassword)
            .query(`
        INSERT INTO Users (FullName, Email, PasswordHash)
        VALUES (@fullName, @email, @passwordHash)
      `);

        res.status(200).json({ success: true, message: 'Đăng ký thành công' });
    } catch (err) {
        console.error('Lỗi đăng ký:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};


exports.login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Thiếu thông tin đăng nhập' });
    }

    try {
        const pool = await poolPromise;

        const result = await pool.request()
            .input('email', email)
            .query('SELECT * FROM Users WHERE Email = @email');

        const user = result.recordset[0];
        if (!user) {
            return res.status(404).json({ success: false, message: 'Email không tồn tại' });
        }

        const match = await bcrypt.compare(password, user.PasswordHash);
        if (!match) {
            return res.status(400).json({ success: false, message: 'Mật khẩu không đúng' });
        }

        const token = jwt.sign(
            { id: user.UserID, email: user.Email }, // sửa Id thành UserID
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );


        res.status(200).json({ success: true, token, message: 'Đăng nhập thành công' });
    } catch (err) {
        console.error('Lỗi đăng nhập:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};



exports.logout = (res) => {
    res.status(200).json({ success: true, message: 'Đăng xuất thành công' });
};


exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Vui lòng nhập email' });
    }

    try {
        const pool = await poolPromise;

        const result = await pool.request()
            .input('email', email)
            .query('SELECT * FROM Users WHERE Email = @email');

        if (result.recordset.length === 0) {
            return res.status(404).json({ success: false, message: 'Email không tồn tại' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expiry = new Date(Date.now() + 3600000); // 1 giờ

        await pool.request()
            .input('email', email)
            .input('token', token)
            .input('expiry', expiry)
            .query('INSERT INTO PasswordReset (Email, Token, Expiry) VALUES (@email, @token, @expiry)');

        await sendResetEmail(email, token);

        res.status(200).json({ success: true, message: 'Đã gửi email khôi phục mật khẩu' });
    } catch (err) {
        console.error('Lỗi quên mật khẩu:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};


exports.changePassword = async (req, res) => {
    const { oldPassword, newPassword, confirmPassword } = req.body;
    const { userId } = req.user;

    if (!oldPassword || !newPassword || !confirmPassword) {
        return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
    }

    if (newPassword !== confirmPassword) {
        return res.status(400).json({ success: false, message: 'Xác nhận mật khẩu không khớp' });
    }

    try {
        const pool = await poolPromise;

        const result = await pool.request()
            .input('userId', userId)
            .query('SELECT * FROM Users WHERE UserID = @userId');

        const user = result.recordset[0];
        if (!user) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });
        }

        const match = await bcrypt.compare(oldPassword, user.PasswordHash);
        if (!match) {
            return res.status(401).json({ success: false, message: 'Mật khẩu cũ không đúng' });
        }

        const hash = await bcrypt.hash(newPassword, 10);

        await pool.request()
            .input('userId', userId)
            .input('passwordHash', hash)
            .query('UPDATE Users SET PasswordHash = @passwordHash WHERE UserID = @userId');

        res.status(200).json({ success: true, message: 'Đổi mật khẩu thành công' });
    } catch (err) {
        console.error('Lỗi đổi mật khẩu:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};

exports.resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ success: false, message: 'Thiếu token hoặc mật khẩu mới' });
    }

    try {
        const pool = await poolPromise;

        const result = await pool.request()
            .input('token', token)
            .query('SELECT * FROM PasswordReset WHERE Token = @token');

        const reset = result.recordset[0];
        if (!reset || new Date(reset.Expiry) < new Date()) {
            return res.status(400).json({ success: false, message: 'Token không hợp lệ hoặc đã hết hạn' });
        }

        const hash = await bcrypt.hash(newPassword, 10);

        await pool.request()
            .input('email', reset.Email)
            .input('passwordHash', hash)
            .query('UPDATE Users SET PasswordHash = @passwordHash WHERE Email = @email');

        await pool.request()
            .input('token', token)
            .query('DELETE FROM PasswordReset WHERE Token = @token');

        res.status(200).json({ success: true, message: 'Đặt lại mật khẩu thành công' });
    } catch (err) {
        console.error('Lỗi đặt lại mật khẩu:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};


exports.loginByPhone = async (req, res) => {
    const { phoneNumber, password } = req.body;

    if (!phoneNumber || !password) {
        return res.status(400).json({ success: false, message: 'Vui lòng nhập số điện thoại và mật khẩu' });
    }

    try {
        const pool = await poolPromise;

        const result = await pool.request()
            .input('phoneNumber', phoneNumber)
            .query('SELECT * FROM Users WHERE PhoneNumber = @phoneNumber');

        const user = result.recordset[0];
        if (!user) {
            return res.status(404).json({ success: false, message: 'Số điện thoại không tồn tại' });
        }

        const match = await bcrypt.compare(password, user.PasswordHash);
        if (!match) {
            return res.status(401).json({ success: false, message: 'Sai mật khẩu' });
        }

        const token = jwt.sign(
            { id: user.Id, email: user.Email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({ success: true, message: 'Đăng nhập thành công', token });
    } catch (err) {
        console.error('Lỗi đăng nhập bằng sdt:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};


exports.forgotPasswordByPhone = async (req, res) => {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
        return res.status(400).json({ success: false, message: 'Vui lòng nhập số điện thoại' });
    }

    try {
        const pool = await poolPromise;

        const result = await pool.request()
            .input('phoneNumber', phoneNumber)
            .query('SELECT * FROM Users WHERE PhoneNumber = @phoneNumber');

        const user = result.recordset[0];
        if (!user) {
            return res.status(404).json({ success: false, message: 'Số điện thoại không tồn tại' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expiry = new Date(Date.now() + 3600000);

        await pool.request()
            .input('email', user.Email)
            .input('token', token)
            .input('expiry', expiry)
            .query('INSERT INTO PasswordReset (Email, Token, Expiry) VALUES (@email, @token, @expiry)');

        await sendResetEmail(user.Email, token); // Gửi qua email liên kết với sdt

        res.status(200).json({ success: true, message: 'Đã gửi email khôi phục mật khẩu' });
    } catch (err) {
        console.error('Lỗi quên mật khẩu bằng sdt:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};


exports.sendOTP = async (req, res) => {
    const { phoneNumber } = req.body;
    if (!phoneNumber) {
        return res.status(400).json({ success: false, message: 'Vui lòng nhập số điện thoại' });
    }

    try {
        const pool = await poolPromise;

        const userCheck = await pool.request()
            .input('phoneNumber', phoneNumber)
            .query('SELECT * FROM Users WHERE PhoneNumber = @phoneNumber');

        if (userCheck.recordset.length === 0) {
            return res.status(404).json({ success: false, message: 'Số điện thoại không tồn tại' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6 số
        const expiry = new Date(Date.now() + 5 * 60000); // 5 phút

        await pool.request()
            .input('phoneNumber', phoneNumber)
            .input('otpCode', otp)
            .input('expiry', expiry)
            .query('INSERT INTO PhoneOTP (PhoneNumber, OTPCode, Expiry) VALUES (@phoneNumber, @otpCode, @expiry)');

        // Gửi OTP qua SMS (tạm thời console log)
        console.log(`OTP gửi đến ${phoneNumber}: ${otp}`);

        res.status(200).json({ success: true, message: 'Đã gửi mã OTP qua số điện thoại' });
    } catch (err) {
        console.error('Lỗi gửi OTP:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};


exports.verifyOTP = async (req, res) => {
    const { phoneNumber, otpCode } = req.body;

    if (!phoneNumber || !otpCode) {
        return res.status(400).json({ success: false, message: 'Thiếu thông tin' });
    }

    try {
        const pool = await poolPromise;

        const result = await pool.request()
            .input('phoneNumber', phoneNumber)
            .input('otpCode', otpCode)
            .query('SELECT * FROM PhoneOTP WHERE PhoneNumber = @phoneNumber AND OTPCode = @otpCode');

        const otp = result.recordset[0];
        if (!otp || new Date(otp.Expiry) < new Date()) {
            return res.status(400).json({ success: false, message: 'Mã OTP không hợp lệ hoặc đã hết hạn' });
        }

        // Xóa OTP sau khi xác thực
        await pool.request()
            .input('phoneNumber', phoneNumber)
            .query('DELETE FROM PhoneOTP WHERE PhoneNumber = @phoneNumber');

        res.status(200).json({ success: true, message: 'Xác thực OTP thành công' });
    } catch (err) {
        console.error('Lỗi xác thực OTP:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};

exports.resetPasswordByPhone = async (req, res) => {
    const { phoneNumber, newPassword } = req.body;

    if (!phoneNumber || !newPassword) {
        return res.status(400).json({ success: false, message: 'Thiếu thông tin' });
    }

    try {
        const pool = await poolPromise;
        const hash = await bcrypt.hash(newPassword, 10);

        await pool.request()
            .input('phoneNumber', phoneNumber)
            .input('passwordHash', hash)
            .query('UPDATE Users SET PasswordHash = @passwordHash WHERE PhoneNumber = @phoneNumber');

        res.status(200).json({ success: true, message: 'Đặt lại mật khẩu thành công' });
    } catch (err) {
        console.error('Lỗi đặt lại mật khẩu:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};

exports.sendOTPByEmail = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Vui lòng nhập email' });
    }

    try {
        const pool = await poolPromise;

        // Kiểm tra email có tồn tại không
        const result = await pool.request()
            .input('email', email)
            .query('SELECT * FROM Users WHERE Email = @email');

        const user = result.recordset[0];
        if (!user) {
            return res.status(404).json({ success: false, message: 'Email không tồn tại' });
        }

        // Tạo mã OTP và thời gian hết hạn
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 phút

        // Lưu OTP vào bảng PasswordReset
        await pool.request()
            .input('email', email)
            .input('token', otp)
            .input('expiry', expiry)
            .query(`
        INSERT INTO PasswordReset (Email, Token, Expiry)
        VALUES (@email, @token, @expiry)
      `);

        // Gửi email chứa mã OTP
        await sendResetEmail(email, null, otp);

        res.status(200).json({ success: true, message: 'Đã gửi mã OTP qua email' });
    } catch (err) {
        console.error('Lỗi gửi OTP qua email:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};

exports.verifyOTPByEmail = async (req, res) => {
    const { email, otpCode } = req.body;

    if (!email || !otpCode) {
        return res.status(400).json({ success: false, message: 'Thiếu thông tin' });
    }

    try {
        const pool = await poolPromise;

        const result = await pool.request()
            .input('email', email)
            .input('token', otpCode)
            .query(`
        SELECT * FROM PasswordReset
        WHERE Email = @email AND Token = @token
      `);

        const record = result.recordset[0];
        if (!record) {
            return res.status(400).json({ success: false, message: 'Mã OTP không đúng' });
        }

        if (new Date(record.Expiry) < new Date()) {
            return res.status(400).json({ success: false, message: 'Mã OTP đã hết hạn' });
        }

        // Xóa OTP sau khi xác thực
        await pool.request()
            .input('email', email)
            .query('DELETE FROM PasswordReset WHERE Email = @email');

        res.status(200).json({ success: true, message: 'Xác thực OTP thành công' });
    } catch (err) {
        console.error('Lỗi xác thực OTP:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};


exports.resetPasswordByEmail = async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ success: false, message: 'Thiếu thông tin' });
    }

    try {
        const pool = await poolPromise;
        const hash = await bcrypt.hash(newPassword, 10);

        await pool.request()
            .input('email', email)
            .input('passwordHash', hash)
            .query('UPDATE Users SET PasswordHash = @passwordHash WHERE Email = @email');

        res.status(200).json({ success: true, message: 'Đặt lại mật khẩu thành công' });
    } catch (err) {
        console.error('Lỗi đặt lại mật khẩu:', err.message);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ' });
    }
};
