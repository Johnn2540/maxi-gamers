const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const hbs = require("hbs");
const Collection = require("./mongodb");

const app = express();
const PORT = 3000;
const JWT_SECRET = "supersecretkey"; // 🔐 put in .env in production

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Set views
app.set("view engine", "hbs");
app.set("views", path.join(__dirname, "../templates"));

// ================== ROUTES ==================

// Landing page
app.get("/", (req, res) => res.render("home"));

// Signup page
app.get("/signup", (req, res) => res.render("signup"));

// Login page
app.get("/login", (req, res) => res.render("login"));

// Reset password page
app.get("/reset-password", (req, res) => res.render("reset-password"));

// ================== SIGNUP ==================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password, role } = req.body;

    // Check if username, email, or phone exists
    const existingUser = await Collection.findOne({ 
      $or: [{ name }, { email }, { phone }] 
    });
    if (existingUser) {
      return res.status(400).send("User with this username, email, or phone already exists.");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user
    const newUser = new Collection({
      name,
      email,
      phone,
      password: hashedPassword,
      role: role || "user"
    });

    await newUser.save();
    res.status(201).send("User registered successfully!");
  } catch (err) {
    res.status(500).send("Error in signup: " + err.message);
  }
});

// ================== LOGIN ==================
app.post("/login", async (req, res) => {
  try {
    const { name, role, password } = req.body;

    // Check user with both name + role
    const user = await Collection.findOne({ name, role });
    if (!user) return res.status(400).send("Invalid username or role");

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send("Invalid password");

    // Create JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Respond differently based on role
    if (user.role === "admin") {
      res.send(`Welcome Admin ${user.name}! Your token: ${token}`);
    } else {
      res.send(`Welcome User ${user.name}! Your token: ${token}`);
    }
  } catch (err) {
    res.status(500).send("Error in login: " + err.message);
  }
});

// ================== RESET PASSWORD ==================
app.post("/reset-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    const user = await Collection.findOne({ email });
    if (!user) return res.status(400).send("Email not found");

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.send("Password reset successfully! You can now login.");
  } catch (err) {
    res.status(500).send("Error resetting password: " + err.message);
  }
});

// ================== START SERVER ==================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});


