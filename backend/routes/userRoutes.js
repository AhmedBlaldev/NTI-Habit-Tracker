const express = require("express");
const { registerUser, loginUser } = require("../controllers/userController");
const auth = require("../middleware/auth");
const User = require("../models/user");

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    res.status(200).json({ success: true, data: { user } });
  } catch (err) {
    console.error("Get user error:", err);
    res.status(500).json({
      success: false,
      message: "Something went wrong. Please try again later.",
    });
  }
});

module.exports = router;