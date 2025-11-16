const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');
const userController = require('../controllers/userController');


// Đăng ký
router.post('/register', authController.register);

// Đăng nhập bằng email
router.post('/login', authController.login);

// Đăng nhập bằng số điện thoại
router.post('/login-phone', authController.loginByPhone);

// Đăng xuất
router.post('/logout', authController.logout);

// Quên mật khẩu bằng email
router.post('/forgot-password', authController.forgotPassword);

// Quên mật khẩu bằng số điện thoại
router.post('/forgot-password-phone', authController.forgotPasswordByPhone);

// Gửi mã OTP qua số điện thoại
router.post('/send-otp', authController.sendOTP);

// Xác thực mã OTP
router.post('/verify-otp', authController.verifyOTP);

// Đặt lại mật khẩu bằng số điện thoại sau khi xác thực OTP
router.post('/reset-password-phone', authController.resetPasswordByPhone);

// Đổi mật khẩu (yêu cầu đăng nhập)
router.post('/change-password', authMiddleware, authController.changePassword);

// Đặt lại mật khẩu bằng token
router.post('/reset-password', authController.resetPassword);

router.post('/send-otp-email', authController.sendOTPByEmail);
router.post('/verify-otp-email', authController.verifyOTPByEmail);
router.post('/reset-password-email', authController.resetPasswordByEmail);
router.post('/login', authController.login);
router.get('/profile', authMiddleware, userController.getProfile);


module.exports = router;