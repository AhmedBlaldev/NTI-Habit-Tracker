const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Username is required"],
      unique: true,
      minlength: [3, "Username must be at least 3 characters"],
      maxlength: [20, "Username must be at most 20 characters"],
      match: [
        /^[a-zA-Z0-9_]{3,20}$/,
        "Username can only contain letters, numbers, and underscores",
      ],
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      match: [
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        "Please provide a valid email address",
      ],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters"],
    },

    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    emailVerificationToken: {
      type: String,
      default: null,
    },
    emailVerificationExpires: {
      type: Date,
      default: null,
    },

    resetPasswordToken: {
      type: String,
      default: null,
    },
    resetPasswordExpires: {
      type: Date,
      default: null,
    },
    passwordChangedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
    indexes: [{ email: 1 }, { username: 1 }, { resetPasswordToken: 1 }],
  }
);

userSchema.methods.createEmailVerificationToken = function () {
  const crypto = require("crypto");
  const emailVerificationToken = crypto.randomBytes(32).toString("hex");

  this.emailVerificationToken = crypto.createHash("sha256").update(emailVerificationToken).digest("hex");
  this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000;

  return emailVerificationToken;
};

userSchema.methods.createPasswordResetToken = function () {
  const crypto = require("crypto");
  const resetToken = crypto.randomBytes(32).toString("hex");
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  this.resetPasswordExpires = Date.now() + 30 * 60 * 1000; // 30 minutes
  return resetToken;
};

userSchema.methods.isResetTokenValid = function (token) {
  const crypto = require("crypto");
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  return (
    this.resetPasswordToken === hashedToken &&
    Date.now() < this.resetPasswordExpires
  );
};

const User = mongoose.model("User", userSchema);

module.exports = User;
