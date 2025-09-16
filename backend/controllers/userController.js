const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const logger = require("../utils/logger");
require("dotenv").config();

// JWT Secret Configuration
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  logger.error("JWT_SECRET is not defined in environment variables");
  process.exit(1);
}

// Validation Regex Constants
const VALIDATION_PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/,
  USERNAME: /^[a-zA-Z0-9_]{3,20}$/,
};

// Security Constants
const SALT_ROUNDS = 10;

const createEmailTransporter = () => {
  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
};


// Helper function to send emails
const sendEmail = async (emailOptions) => {
  try {
    const transporter = createEmailTransporter();
    logger.info("Sending email", {
      to: emailOptions.to,
      subject: emailOptions.subject,
    });

    const info = await transporter.sendMail(emailOptions);

    logger.info("Email sent successfully", {
      messageId: info.messageId,
      to: emailOptions.to,
    });

    return { success: true, messageId: info.messageId };
  } catch (error) {
    logger.error("Email sending failed", {
      error: error.message,
      to: emailOptions.to,
      subject: emailOptions.subject,
    });
    throw new Error("Failed to send email");
  }
};

const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.user.id;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    if (newPassword !== confirmNewPassword) {
      return res.status(400).json({
        success: false,
        message: "New password and confirm password do not match",
      });
    }

    if (!validationPassword(newPassword)) {
      return res.status(400).json({
        success: false,
        message:
          "New password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number",
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const isCurrentPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password
    );
    if (!isCurrentPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({
        success: false,
        message: "New password must be different from the current password",
      });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

    user.password = hashedNewPassword;
    user.passwordChangedAt = Date.now();
    await user.save({ validateBeforeSave: false });

    logger.info("Password changed successfully", {
      userId: req.user.id,
    });

    res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (error) {
    logger.error("Password change failed", {
      error: error.message,
      userId: req.user?.id,
      stack: error.stack,
    });
    res.status(500).json({
      success: false,
      message: "Something went wrong. Please try again later.",
    });
  }
};

const forgetPassword = async (req, res) => {
  try {
    const { email } = req.body;
    logger.info("Password reset request received", { email });

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    if (!VALIDATION_PATTERNS.EMAIL.test(email)) {
      logger.warn("Invalid email format in password reset", { email });
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email",
      });
    }

    logger.debug("Searching for user in database", { email });
    const user = await User.findOne({ email });
    if (!user) {
      logger.info("Password reset requested for non-existent user", { email });
      return res.status(200).json({
        success: true,
        message:
          "If that email is registered, you will receive a password reset link",
      });
    }

    logger.debug("Creating password reset token", { userId: user._id });
    const resetToken = user.createPasswordResetToken();

    logger.debug("Saving user with reset token", { userId: user._id });
    await user.save({ validateBeforeSave: false });

    const resetURL = `${
      process.env.FRONTEND_URL || "http://localhost:3000"
    }/reset-password/${resetToken}`;

    const emailOptions = {
      from: `"Support Team" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset Request",
      text: `You requested a password reset. Click the link to reset your password: ${resetURL}. If you did not request this, please ignore this email.`,
    };

    await sendEmail(emailOptions);

    res.status(200).json({
      success: true,
      message:
        "If that email is registered, you will receive a password reset link",
    });
  } catch (error) {
    const foundUser = await User.findOne({ email: req.body.email });
    if (foundUser) {
      foundUser.resetPasswordToken = null;
      foundUser.resetPasswordExpires = null;
      await foundUser.save({ validateBeforeSave: false });
    }

    logger.error("Password reset request failed", {
      error: error.message,
      email: req.body.email,
      stack: error.stack,
    });
    res.status(500).json({
      success: false,
      message: "Something went wrong. Please try again later.",
    });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;

    if (!password || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Password and confirm password are required",
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Passwords do not match",
      });
    }

    if (!VALIDATION_PATTERNS.PASSWORD.test(password)) {
      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number",
      });
    }

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Token is invalid or has expired",
      });
    }

    const saltRounds = SALT_ROUNDS;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    user.passwordChangedAt = Date.now();

    await user.save();

    const jwtToken = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    logger.info("Password reset completed successfully", {
      userId: user._id,
      email: user.email,
    });

    res.status(200).json({
      success: true,
      message: "Password has been reset successfully",
      data: {
        user: { id: user._id, username: user.username, email: user.email },
        token: jwtToken,
      },
    });
  } catch (error) {
    logger.error("Password reset failed", {
      error: error.message,
      token: req.params.token,
      stack: error.stack,
    });
    res.status(500).json({
      success: false,
      message: "Something went wrong. Please try again later.",
    });
  }
};

// Validation Functions
const validationEmail = (email) => {
  return VALIDATION_PATTERNS.EMAIL.test(email);
};

const validationPassword = (password) => {
  return VALIDATION_PATTERNS.PASSWORD.test(password);
};

const validationUsername = (username) => {
  return VALIDATION_PATTERNS.USERNAME.test(username);
};

const registerUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Username, email and password are required",
      });
    }

    if (!validationUsername(username)) {
      return res.status(400).json({
        success: false,
        message:
          "Username must be 3-20 characters long and can only contain letters, numbers, and underscores",
      });
    }

    if (!validationEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email",
      });
    }

    if (!validationPassword(password)) {
      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User with this email already exists",
      });
    }

    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({
        success: false,
        message: "Username is already taken",
      });
    }

    const saltRounds = SALT_ROUNDS;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const user = new User({
      username,
      email,
      password: hashedPassword,
      isEmailVerified: false,
    });

    const verificationToken = user.createEmailVerificationToken();
    await user.save({ validateBeforeSave: false });

    const verificationURL = `${
      process.env.FRONTEND_URL || "http://localhost:3000"
    }/verify-email/${verificationToken}`;
    const emailOptions = {
      from: `"Support Team" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Email Verification",
      html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Hi ${username}! 🎉</h2>
          <p>Thank you for signing up for Habit Tracker</p>
          <p>To start using your account, you need to verify your email first:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationURL}" 
               style="background-color: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
              Verify Email ✅
            </a>
          </div>
          
          <p>Or copy this link into your browser:</p>
          <p style="word-break: break-all; background-color: #f5f5f5; padding: 10px;">${verificationURL}</p>

          <p><strong>Important:</strong> This link is only valid for 24 hours!</p>
          <p>If you didn't sign up, please ignore this email.</p>
        </div>
        `,
    };

    await sendEmail(emailOptions);

    res.status(201).json({
      success: true,
      message: "User created successfully. Please verify your email.",
      data: {
        id: user._id,
        username,
        email,
        isEmailVerified: false,
      },
    });
  } catch (err) {
    logger.error("User registration failed", {
      error: err.message,
      email: req.body.email,
      username: req.body.username,
      stack: err.stack,
    });
    res.status(500).json({
      success: false,
      message: "Registration failed",
    });
  }
};

// إصلاح دالة verifyEmail
const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;
    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Verification token is required",
      });
    }
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Token is invalid or has expired",
      });
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = null;
    user.emailVerificationExpires = null;

    await user.save();

    const jwtToken = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    logger.info("Email verification completed successfully", {
      userId: user._id,
      email: user.email,
    });

    res.status(200).json({
      success: true,
      message: "Email successfully verified! Welcome 🎉",
      data: {
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          isEmailVerified: true,
        },
        token: jwtToken,
      },
    });
  } catch (error) {
    logger.error("Email verification failed", {
      error: error.message,
      token: req.params.token,
      stack: error.stack,
    });
    res.status(500).json({
      success: false,
      message: "Something went wrong. Please try again later.",
    });
  }
};

const resetEmailVerification = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }
    if (user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        message: "Email is already verified",
      });
    }

    const verificationToken = user.createEmailVerificationToken();
    await user.save({ validateBeforeSave: false });

    const verificationURL = `${
      process.env.FRONTEND_URL || "http://localhost:3000"
    }/verify-email/${verificationToken}`;
    const emailOptions = {
      from: `"Support Team" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Resend Verification Link",
      html: `
      <h2>Resend Verification Link</h2>
      <p>Click the link below to verify your account:</p>
      <a href="${verificationURL}">Verify Email</a>
      <p>The link is valid for 24 hours.</p>
      `,
    };

    await sendEmail(emailOptions);

    res.status(200).json({
      success: true,
      message: "Verification email resent. Please check your inbox.",
    });
  } catch (error) {
    logger.error("Resend verification email failed", {
      error: error.message,
      email: req.body.email,
      stack: error.stack,
    });
    res.status(500).json({
      success: false,
      message: "Something went wrong. Please try again later.",
    });
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }
    if (!user.isEmailVerified) {
      return res.status(401).json({
        success: false,
        message: "Please verify your email before logging in",
        needsEmailVerification: true,
      });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });

    logger.info("User login successful", {
      userId: user._id,
      email: email,
    });

    res.status(200).json({
      success: true,
      message: "Login successful",
      data: {
        user: {
          id: user._id,
          username: user.username,
          email,
          isEmailVerified: user.isEmailVerified,
        },
        token,
      },
    });
  } catch (err) {
    logger.error("User login failed", {
      error: err.message,
      email: req.body.email,
      stack: err.stack,
    });
    res.status(500).json({
      success: false,
      message: "Something went wrong. Please try again later.",
    });
  }
};
module.exports = {
  registerUser,
  loginUser,
  forgetPassword,
  resetPassword,
  changePassword,
  verifyEmail,
  resetEmailVerification,
};
