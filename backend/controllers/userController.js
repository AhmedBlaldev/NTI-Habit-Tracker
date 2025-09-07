const User = require("../models/User");
const bcrypt = require("bcryptjs");

const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({message: "Email and password are required"});
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({message: "User not found"});
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({message: "Invalid password"});
        }
        res.status(200).json({message: "Login successful", user});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

const registerUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const encryptedPassword = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, encryptedPassword);
    const user = new User({ 
        username, 
        email, 
        password: hashedPassword });

    await user.save();

    res
      .status(201)
      .json({ message: "User created successfully", user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

module.exports = { registerUser, loginUser };
