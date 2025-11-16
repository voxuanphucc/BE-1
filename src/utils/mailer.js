const nodemailer = require('nodemailer');

exports.sendResetEmail = async (email, token = null, otpCode = null) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    let subject = 'Khôi phục mật khẩu';
    let htmlContent = '';

    if (otpCode) {
        subject = 'Mã OTP khôi phục mật khẩu';
        htmlContent = `
      <p>Xin chào,</p>
      <p>Mã OTP của bạn là: <strong>${otpCode}</strong></p>
      <p>Vui lòng không chia sẻ mã này với bất kỳ ai. Mã có hiệu lực trong 5 phút.</p>
    `;
    } else if (token) {
        const link = `http://localhost:5173/reset-password?token=${token}`;
        htmlContent = `
      <p>Click vào link để đặt lại mật khẩu:</p>
      <p><a href="${link}">${link}</a></p>
    `;
    } else {
        throw new Error('Thiếu token hoặc mã OTP để gửi email');
    }

    await transporter.sendMail({
        from: `"Shop điện tử" <${process.env.EMAIL_USER}>`,
        to: email,
        subject,
        html: htmlContent
    });
};