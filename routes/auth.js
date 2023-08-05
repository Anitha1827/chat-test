const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const router = express.Router();
const User = require("../models/User");

// Middleware to check if the request is from an admin user
const isAdminUser = async (req, res, next) => {
  const user = req.user; // Assuming you are extracting the user ID from the JWT
  if (!user || !user.isAdmin) {
    return res.status(403).json({ message: 'Access denied. Only admin users allowed.' });
  }
  next();
};

router.get("/users", isAdminUser, async (req, res) => {
  try {
    // Fetch all user data from the database
    const users = await User.find().select("-password");
    res.status(200).json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate that the required fields are present
    if (!username || !password || !email) {
      return res
        .status(400)
        .json({ error: "Please provide all required fields." });
    }

    // Check if any user exists
    const userCount = await User.countDocuments();
    const isAdmin = userCount === 0; // First user will be the admin

    // Check if the username already exist
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: "username already exists" });
    }

    // Hash the password
    // const hashedPassword = await bcrypt.hash(password, 10);
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    //Create new user
    const user = new User({
      email,
      password: hashedPassword,
      username,
    });

    //save the user to database
    await user.save();
    
    //Generate JWT
    const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY);

    res.status(200).json({ message: "User registered Successfully", token });
  } catch (error) {
    console.error("Error registering user", error);
    res.status(5000).json({ message: "Internal server error" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    //check if the email exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid usename or password" });
    }

    // Compare the password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    //generate jwt
    const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.SECRET_KEY);

    res.status(200).json({ message: "Login successful", token, user });
  } catch (error) {
    console.error("Error logging in", error);
    res.status(500).json({ message: "An error occured " });
  }
});

module.exports = router;
