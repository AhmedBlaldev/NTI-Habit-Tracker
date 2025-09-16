const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
require("dotenv").config();

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

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedNewPassword;
    user.passwordChangedAt = Date.now();
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error("Change Password Error:", error);
    res.status(500).json({
      success: false,
      message: "Something went wrong. Please try again later.",
    });
  }
};

const createEmailTransporter = async () => {
  return (transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  }));
};

const forgetPassword = async (req, res) => {
  try {
    const { email } = req.body;
    console.log("Email received: ", email);

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email",
      });
    }

    console.log("Looking for user...");
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(200).json({
        success: true,
        message:
          "If that email is registered, you will receive a password reset link",
      });
    }

    console.log("Creating reset token...");
    const resetToken = user.createPasswordResetToken();
    console.log("Saving user...");
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
    const transporter = await createEmailTransporter();
    console.log("📤 Sending email via Gmail...");
    const info = await transporter.sendMail(emailOptions);
    console.log("✅ Email sent! Message ID:", info.messageId);

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

    console.error("Forget Password Error:", error);
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

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
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
    const encryptedPassword = 10;
    const hashedPassword = await bcrypt.hash(password, encryptedPassword);

    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    user.passwordChangedAt = Date.now();

    await user.save();

    const jwtToken = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: "1h",
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
    console.error("Reset Password Error:", error);
    res.status(500).json({
      success: false,
      message: "Something went wrong. Please try again later.",
    });
  }
};

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("JWT_SECRET is not defined in environment variables");
}

// Validation Functions
const validationEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validationPassword = (password) => {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

const validationUsername = (username) => {
  const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
  return usernameRegex.test(username);
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
          "Username must be 3-30 characters long and can only contain letters, numbers, and underscores",
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

    const encryptedPassword = 10;
    const hashedPassword = await bcrypt.hash(password, encryptedPassword);
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
    const transporter = await createEmailTransporter();
    await transporter.sendMail(emailOptions);

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
    console.error("Error during user registration:", err);
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
    console.error("Email Verification Error:", error);
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
    const transporter = await createEmailTransporter();
    await transporter.sendMail(emailOptions);

    res.status(200).json({
      success: true,
      message: "Verification email resent. Please check your inbox.",
    });
  } catch (error) {
    console.error("Resend Verification Email Error:", error);
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
    console.log("Login Error:", err);
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
