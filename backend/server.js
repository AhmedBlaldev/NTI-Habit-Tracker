const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();

app.use(cors({
  origin: [
    'http://localhost:4200',
    'https://nti-habit-tracker.up.railway.app', 
    'https://*.vercel.app', 
    'https://*.railway.app' 
  ],
  credentials: true
}));

app.use(express.json());

const userRoutes = require("./routes/userRoutes");
const habitRoutes = require("./routes/habitRoutes");

app.use("/api/users", userRoutes);
app.use("/api/habits", habitRoutes);

app.get("/", (req, res) => {
  res.send("API is running...");
});

app.get("/api", (req, res) => {
  res.send("Habit Tracker API is running...");
});

mongoose.connect(process.env.MONGO_URI || "mongodb://localhost:27017/habittracker")
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 URL: http://localhost:${PORT}`);
});