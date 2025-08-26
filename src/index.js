const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const hbs = require("hbs");
const User = require("./mongodb"); 
const session = require("express-session");

const app = express();
const PORT = 3000;
const JWT_SECRET = "supersecretkey"; // ⚠️ use .env in production

// ================== MIDDLEWARE ==================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: "yourSecretKey", 
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // true if https
  })
);

// ✅ Serve static assets
app.use(express.static(path.join(__dirname, "../public")));

// ================== VIEW ENGINE ==================
app.set("view engine", "hbs");
app.set("views", path.join(__dirname, "../templates"));

// ================== ROUTES ==================

// Pages
app.get("/", (req, res) => res.render("home"));
app.get("/user", (req, res) => res.render("user"));
app.get("/admin", (req, res) => res.render("admin"));
app.get("/signup", (req, res) => res.render("signup"));
app.get("/login", (req, res) => res.render("login"));
app.get("/reset-password", (req, res) => res.render("reset-password"));
app.get("/gaming", (req, res) => res.render("gaming"));
app.get("/loans", (req, res) => res.render("loans"));
app.get("/shop", (req, res) => res.render("shop"));
app.get("/blog", (req, res) => res.render("blog"));
app.get("/contact", (req, res) => res.render("contact"));
app.get("/about", (req, res) => res.render("about"));
app.get("/privacy-policy", (req, res) => res.render("privacy-policy"));
app.get("/terms", (req, res) => res.render("terms"));
app.get("/profile", (req, res) => res.render("profile"));


// ================== SIGNUP ==================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password, studentId } = req.body;

    // Check if email or phone already exists
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      return res
        .status(400)
        .send("User with this email or phone already exists.");
    }

    // Build user object
    const userData = {
      name,
      email,
      phone,
      password, // hashed by pre("save")
      role: "user", // enforce role = user
    };

    if (studentId && studentId.trim() !== "") {
      userData.studentId = studentId;
    }

    const newUser = new User(userData);
    await newUser.save();

    res.redirect("/user");

  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).send("Duplicate email or phone.");
    }
    res.status(500).send("Error in signup: " + err.message);
  }
});


// ================== LOGIN ==================
app.post("/login", async (req, res) => {
  try {
    const { name, password, role } = req.body;

    // Find user by name
    const user = await User.findOne({ name });
    if (!user) return res.status(400).send("User not found");

    // Compare hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send("Invalid password");

    // Check role consistency
    if (role !== user.role) {
      return res.status(403).send("You are not authorized to log in as this role");
    }

    // Store in session
    req.session.user = {
      id: user._id,
      name: user.name,
      role: user.role,
    };

    // Redirect by role
    if (user.role === "admin") {
      return res.redirect("/admin");
    } else {
      return res.redirect("/user");
    }

  } catch (err) {
    res.status(500).send("Error logging in: " + err.message);
  }
});



// ================== RESET PASSWORD ==================
app.post("/reset-password", async (req, res) => {
  try {
    const { name, email, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).send("Passwords do not match");
    }

    const user = await User.findOne({ name, email });
    if (!user) return res.status(400).send("Invalid username or email");

    user.password = newPassword; // will hash in pre("save")
    await user.save();

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.redirect(`/user?token=${token}`);
  } catch (err) {
    res.status(500).send("Error resetting password: " + err.message);
  }
});


// ================== START SERVER ==================
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

