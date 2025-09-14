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
  },
  {
    timestamps: true,
    indexes: [{ email: 1 }, { username: 1 }],
  }
);

userSchema.pre("save", async function (next) {
  if (this.isNew) {
    const existingEmail = await this.constructor.findOne({ email: this.email });
    const existingUsername = await this.constructor.findOne({
      username: this.username,
    });

    if (existingEmail) {
      throw new Error("Email already exists");
    }
    if (existingUsername) {
      throw new Error("Username already exists");
    }
  }
  next();
});

const User = mongoose.model("User", userSchema);

module.exports = User;
