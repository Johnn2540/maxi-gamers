require("dotenv").config();

// ================== IMPORTS ==================
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const hbs = require("hbs");
const session = require("express-session");
const multer = require("multer");
const http = require("http");
const { Server } = require("socket.io");
const { User, Product, Leaderboard, Booking, TopBarMessage, Loan, Message } = require("./mongodb");
const MongoStore = require('connect-mongo');
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const crypto = require("crypto");
const nodemailer = require("nodemailer");

// ================== APP & SERVER ==================
const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey"; // fallback if env not set

// ================== CLOUDINARY CONFIG ==================
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

// ================== CLOUDINARY STORAGE ==================
const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => ({
    folder: "loans",
    public_id: Date.now() + "-" + file.originalname.split(".")[0],
  }),
});

const upload = multer({ storage });

// ================== SESSION CONFIG ==================
app.use(
  session({
    name: "connect.sid",
    secret: process.env.SESSION_SECRET || "yourSecretKey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI, // make sure this matches your .env
      collectionName: "sessions",
      ttl: 7 * 24 * 60 * 60, // 7 days
    }),
  })
);

// ================== PASSPORT GOOGLE OAUTH ==================
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          user = await User.create({
            googleId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            image: profile.photos[0].value,
            role: "user",
            active: true,
          });
        }
        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

// ================== PASSPORT SERIALIZE / DESERIALIZE ==================
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// ================== INITIALIZE PASSPORT ==================
app.use(passport.initialize());
app.use(passport.session());

// Start Google OAuth login
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Google OAuth callback
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful login, store user in session
    req.session.user = { 
      id: req.user._id, 
      name: req.user.name, 
      role: req.user.role 
    };

    // Redirect based on role
    if (req.user.role === 'admin') return res.redirect('/admin');
    return res.redirect('/user');
  }
);


// ================== MIDDLEWARE ==================
app.set("trust proxy", 1); // required on Render/Heroku
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// ================== DEBUG ==================
console.log("GOOGLE_CLIENT_ID loaded:", !!process.env.GOOGLE_CLIENT_ID);
console.log("Mongo URI loaded:", !!process.env.MONGO_URI);
console.log("Session Secret loaded:", !!process.env.SESSION_SECRET);
console.log("JWT Secret loaded:", !!process.env.JWT_SECRET);


// ================== AUTH MIDDLEWARE ==================

/**
 * Ensures that the user is logged in and active.
 * Attaches the DB-fetched user to req.user.
 * Optionally redirects users based on role.
 */
async function ensureAuthenticated(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login"); // Not logged in
  }

  try {
    const user = await User.findById(req.session.user.id);

    if (!user) {
      req.session.destroy(() => res.status(403).send("User not found."));
      return;
    }

    if (!user.active) {
      req.session.destroy(() => res.status(403).send("Your account is suspended."));
      return;
    }

    req.user = user; // Attach user to request for downstream middleware

    // Auto-redirect based on role if hitting the default dashboard route
    if (req.path === "/dashboard" || req.path === "/") {
      if ((user.role || "").toLowerCase() === "admin") return res.redirect("/admin");
      return res.redirect("/user");
    }

    next();
  } catch (err) {
    console.error("Auth check error:", err);
    res.status(500).send("Internal server error");
  }
}

/**
 * Ensures the logged-in user is an admin.
 * Use after ensureAuthenticated middleware.
 */
function requireAdmin(req, res, next) {
  if (!req.user || (req.user.role || "").toLowerCase() !== "admin") {
    return res.status(403).send("Access denied. Admins only.");
  }
  next();
}

module.exports = {
  ensureAuthenticated,
  requireAdmin
};

// ================== VIEW ENGINE ==================
app.set("view engine", "hbs");
app.set("views", path.join(__dirname, "../templates"));

// ================== HBS HELPERS ==================
hbs.registerHelper("eq", (a, b) => a === b);
hbs.registerHelper("ne", (a, b) => a !== b);
hbs.registerHelper("and", (a, b) => a && b);
hbs.registerHelper("or", (a, b) => a || b);
hbs.registerHelper("inc", value => parseInt(value) + 1);
hbs.registerHelper("chunk", (array, size) => {
  let chunked = [];
  for (let i = 0; i < array.length; i += size) {
    chunked.push(array.slice(i, i + size));
  }
  return chunked;
});

// ================== SOCKET.IO ==================
io.on("connection", socket => {
  console.log("User connected:", socket.id);
});


// ================== ROUTES ==================

// --------- HOME ---------
app.get("/", async (req, res) => {
  try {
    const saleProducts = await Product.find({ onSale: true }).limit(6);
    res.render("home", { saleProducts });
  } catch (err) {
    res.status(500).send("Error loading products");
  }
});

// --------- ADMIN DASHBOARD ---------
app.get("/admin", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") return res.status(403).send("Access Denied");
  try {
    const [users, products, leaderboard] = await Promise.all([
      User.find(),
      Product.find(),
      Leaderboard.find().sort({ score: -1 }),
    ]);
    res.render("admin", { users, products, leaderboard });
  } catch (err) {
    res.status(500).send("Error loading admin panel: " + err.message);
  }
});

// ================== ADMIN USER ROUTES ==================

// Get all users (JSON for admin panel)
app.get("/admin/users/json", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Toggle user active/suspended
app.post("/admin/users/toggle/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    user.active = !user.active;
    await user.save();

    res.json({ success: true, active: user.active });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Toggle role (admin <-> user)
app.post("/admin/users/role/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    user.role = user.role === "admin" ? "user" : "admin";
    await user.save();

    res.json({ success: true, role: user.role });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Delete user
app.post("/admin/users/delete/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ===== ADMIN: fetch all users JSON =====
app.get("/admin/users/json", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Access denied" });
  }

  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ success: false, message: "Failed to load users" });
  }
});

// Get single user by ID and render edit form
app.get("/admin/users/edit/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).lean();
    if (!user) {
      return res.status(404).send("User not found");
    }

    // Render an EJS/handlebars view called "admin/edit-user"
    res.render("admin/edit-user", { user });
  } catch (err) {
    console.error("Error loading edit page:", err);
    res.status(500).send("Server error");
  }
});
// ================== ADMIN UPDATE USER ==================
app.post("/admin/users/update/:id", async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== "admin") {
      return res.status(403).send("Access denied");
    }

    const { name, email, role } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      { name, email, role },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).send("User not found");
    }

    // After update, go back to user list
    res.redirect("/admin");
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).send("Failed to update user");
  }
});


// ================== ADMIN PRODUCTS JSON ==================
app.get("/admin/products/json", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") 
    return res.status(403).json({ success: false, message: "Access denied" });

  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    console.error("Error loading admin products:", err);
    res.status(500).json({ success: false, message: "Failed to load products" });
  }
});

// ================== PRODUCTS JSON FOR SHOP ==================
app.get("/products/json", async (req, res) => {
  try {
    const products = await Product.find();
    const productsWithPath = products.map(p => ({
      ...p.toObject(),
      image: p.image || null // Cloudinary URL or null
    }));
    res.json(productsWithPath);
  } catch (err) {
    console.error("Failed to fetch products:", err);
    res.status(500).json({ success: false, message: "Failed to fetch products" });
  }
});


// --------- TOP LEADERBOARD ---------
app.get("/top-leaderboard", async (req, res) => {
  try {
    const topPlayers = await Leaderboard.find().sort({ score: -1 }).limit(10);
    res.json(topPlayers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================== ADMIN LEADERBOARD ROUTES ==================
app.post("/admin/leaderboard", async (req, res) => {
  try {
    const { player, score } = req.body;
    if (!player || score == null) {
      return res.json({ success: false, message: "Player and score required" });
    }

    const newPlayer = await Leaderboard.create({ player, score });
    io.emit("leaderboardUpdate", newPlayer);

    // 👉 return JSON (not redirect)
    res.json({ success: true, entry: newPlayer });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


app.put("/admin/leaderboard/:id", async (req, res) => {
  try {
    const { player, score } = req.body;
    await Leaderboard.findByIdAndUpdate(req.params.id, { player, score });
    io.emit("leaderboardUpdate");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete("/admin/leaderboard/:id", async (req, res) => {
  try {
    await Leaderboard.findByIdAndDelete(req.params.id);
    io.emit("leaderboardUpdate");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ================== ADMIN PRODUCT ROUTES ==================
app.post("/admin/products", upload.single("image"), async (req, res) => {
  try {
    const { title, marketPrice, salePrice, description, onSale } = req.body;
    let imageUrl = null;

    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: "products"
      });
      imageUrl = result.secure_url;
    }

    const newProduct = await Product.create({
      title,
      marketPrice,
      salePrice,
      description,
      onSale: onSale === "on" || onSale === "true",
      image: imageUrl
    });

    io.emit("newProduct", newProduct);
    res.json({ success: true, product: newProduct });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/admin/products/edit/:id", upload.single("image"), async (req, res) => {
  try {
    const { title, marketPrice, salePrice, description, onSale } = req.body;
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ success: false, message: "Product not found" });

    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: "products"
      });
      product.image = result.secure_url;
    }

    Object.assign(product, { title, marketPrice, salePrice, description, onSale: onSale === "on" || onSale === "true" });
    await product.save();

    io.emit("updateProduct", product);
    res.json({ success: true, product });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


app.post("/admin/products/delete/:id", async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ success: false, message: "Product not found" });
    io.emit("deleteProduct", product._id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ================== USER LOANS ==================

// Render user's loans page (HTML)
app.get("/loans", async (req, res) => {
  try {
    if (!req.session.user) return res.redirect("/login");

    const loans = await Loan.find({ user: req.session.user.id }).sort({ createdAt: -1 });
    res.render("loans", { loans });
  } catch (err) {
    console.error("Error loading user loans:", err);
    res.status(500).send("Failed to load loans");
  }
});

// Create new loan
app.post("/loans", upload.single("itemImage"), async (req, res) => {
  try {
    if (!req.session.user) {
      if (req.headers.accept?.includes("application/json")) {
        return res.status(403).json({ success: false, message: "Login required" });
      }
      return res.redirect("/login");
    }

    // When using CloudinaryStorage, req.file.path is the full Cloudinary URL
    const loan = await Loan.create({
      user: req.session.user.id,
      itemImage: req.file ? req.file.path : null,   //  Cloudinary URL instead of local filename
      description: req.body.description,
      itemValue: req.body.itemValue,
      loanAmount: req.body.loanAmount,
      loanPeriod: req.body.loanPeriod,
      status: "Pending",
    });

    // Broadcast new loan to admins
    io.emit("loanCreated", loan);

    if (req.headers.accept?.includes("application/json")) {
      return res.json({ success: true, loan });
    }

    res.redirect("/loans");
  } catch (err) {
    console.error("Loan submission error:", err);
    if (req.headers.accept?.includes("application/json")) {
      return res.status(500).json({ success: false, message: err.message });
    }
    res.status(500).send("Failed to submit loan");
  }
});

// Fetch logged-in user's loans (AJAX/json)
app.get("/loans/list", async (req, res) => {
  try {
    if (!req.session.user) return res.json([]);
    const loans = await Loan.find({ user: req.session.user.id }).sort({ createdAt: -1 });
    res.json(loans);
  } catch (err) {
    console.error("Error fetching user loans:", err);
    res.status(500).json([]);
  }
});


// ================== ADMIN LOANS ==================

// Render admin loans page
app.get("/admin/loans", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Access Denied");
  }
  try {
    const loans = await Loan.find()
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    // images are already part of Loan schema, so they’ll be available here
    res.render("admin-loans", { loans });
  } catch (err) {
    console.error("Error loading admin loans:", err);
    res.status(500).send("Failed to load loans");
  }
});

// JSON for admin fetch/AJAX
app.get("/admin/loans/json", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Access denied" });
  }
  try {
    const loans = await Loan.find()
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    // includes images array
    res.json(loans);
  } catch (err) {
    console.error("Error fetching admin loans:", err);
    res.status(500).json([]);
  }
});

// Admin update loan status
app.post("/admin/loans/:id/status", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Access denied" });
  }

  const { status } = req.body;
  try {
    const loan = await Loan.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).populate("user", "name email");

    if (!loan) {
      return res.status(404).json({ success: false, message: "Loan not found" });
    }

    // Broadcast update (frontend can refresh automatically)
    io.emit("loanUpdated", loan);

    res.json({ success: true, loan });
  } catch (err) {
    console.error("Loan update error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});


// ================== SIGNUP (JWT Only) ==================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password, studentId } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) return res.status(400).send("User already exists");

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new inactive user
    const newUser = await User.create({
      name,
      email,
      phone,
      password: hashedPassword,
      role: "user",
      studentId,
      active: false, // requires email verification
    });

    // Generate JWT token for email verification
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });

    // Prepare verification email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    const baseUrl = process.env.BASE_URL || "http://localhost:3000";
    const verifyUrl = `${baseUrl}/verify-email-jwt?token=${token}`;

    await transporter.sendMail({
      to: email,
      subject: "Verify your email",
      html: `<p>Hello ${name},</p>
             <p>Please verify your email by clicking the link below:</p>
             <a href="${verifyUrl}">${verifyUrl}</a>`,
    });

    res.send("Signup successful! Please check your email to verify your account.");
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).send("Error during signup. Please try again.");
  }
});

// ================== EMAIL VERIFICATION ==================
app.get("/verify-email-jwt", async (req, res) => {
  const { token } = req.query;

  if (!token) return res.status(400).send("Verification token is missing.");

  try {
    // Decode JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Find user
    const user = await User.findOne({ email: decoded.email });
    if (!user) return res.status(400).send("Invalid or expired token.");

    // Activate user if not already active
    if (!user.active) {
      user.active = true;
      await user.save();
    }

    // Auto-login via session
    req.session.user = { id: user._id, name: user.name, role: user.role };

    // Redirect based on role
    res.redirect(user.role === "admin" ? "/admin" : "/user");
  } catch (err) {
    console.error("Email verification error:", err);

    // Handle JWT-specific errors
    if (err.name === "TokenExpiredError") {
      return res.status(400).send("Verification link has expired. Please signup again.");
    } else if (err.name === "JsonWebTokenError") {
      return res.status(400).send("Invalid verification token.");
    }

    res.status(500).send("Error verifying email. Please try again.");
  }
});


// ================== LOGIN ==================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase().trim() });

    if (!user) return res.status(400).send("Invalid email or password");

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send("Invalid email or password");

    // If user exists but not verified
    if (!user.active && user.role !== "admin") {
      // redirect to a resend verification page
      return res.redirect(`/resend-verification?email=${encodeURIComponent(email)}`);
    }

    // Store minimal session data
    req.session.userId = user._id;

    // Role-based redirect
    const redirectMap = { admin: "/admin", user: "/user" };
    res.redirect(redirectMap[user.role] || "/");
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("Login failed. Please try again.");
  }
});

// ================== RESET PASSWORD ==================
app.post("/reset-password", async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword)
      return res.status(400).send("Passwords do not match");

    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("Invalid email");

    // Allow password reset for existing users/admins
    if (!user.active && user.role === "user") {
      return res.status(403).send("Please verify your email or contact admin");
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.send("Password reset successful. You can now login.");
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).send("Error resetting password. Please try again.");
  }
});

// ================== GAMING BOOKINGS ==================

// User creates a new booking
app.post("/gaming/book", async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(403).json({ success: false, message: "Login required" });
    }

    const { game, console, date, timeSlot } = req.body;
    const booking = await Booking.create({
      user: req.session.user.id,   // correct field name from schema
      game,
      console,
      date,
      timeSlot
    });

    const populatedBooking = await Booking.findById(booking._id)
      .populate("user", "name email");

    // Notify all admins/clients via socket.io
    io.emit("newBooking", { ...populatedBooking.toObject(), isNew: true });

    res.json({ success: true, booking: populatedBooking });
  } catch (err) {
    console.error("Error creating booking:", err);
    res.status(500).json({ success: false, message: "Failed to create booking" });
  }
});

// Admin updates booking status
app.post("/admin/bookings/update/:id", async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    const { status } = req.body;
    const booking = await Booking.findById(req.params.id);

    if (!booking) {
      return res.status(404).json({ success: false, message: "Booking not found" });
    }

    booking.status = status;
    await booking.save();

    const populatedBooking = await Booking.findById(booking._id)
      .populate("user", "name email");

    // Notify all clients about update
    io.emit("updateBooking", populatedBooking);

    res.json({ success: true, booking: populatedBooking });
  } catch (err) {
    console.error("Error updating booking:", err);
    res.status(500).json({ success: false, message: "Failed to update booking" });
  }
});

// Admin fetch all bookings
app.get("/admin/bookings/json", async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    const bookings = await Booking.find()
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    const now = new Date();
    const bookingsWithFlag = bookings.map(b => {
      const bookingObj = b.toObject();

      // prevent crash if user is missing
      if (!bookingObj.user) {
        bookingObj.user = { name: "Unknown User", email: "N/A" };
      }

      const createdAt = b.createdAt instanceof Date ? b.createdAt : null;
      bookingObj.isNew = createdAt ? ((now - createdAt) / 1000 < 10) : false;
      bookingObj.createdAt = createdAt;

      return bookingObj;
    });

    res.json(bookingsWithFlag); // always array
  } catch (err) {
    console.error("Error fetching admin bookings:", err);
    res.status(500).json([]); // keep array shape
  }
});

// User fetch their own bookings
app.get("/gaming/bookings/json", async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(403).json({ success: false, message: "Login required" });
    }

    const bookings = await Booking.find({ user: req.session.user.id })
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    // make sure every booking has a safe user object
    const safeBookings = bookings.map(b => {
      const bookingObj = b.toObject();
      if (!bookingObj.user) {
        bookingObj.user = { name: "Unknown User", email: "N/A" };
      }
      return bookingObj;
    });

    res.json(safeBookings); // always array
  } catch (err) {
    console.error("Error fetching user bookings:", err);
    res.status(500).json([]); // keep array shape
  }
});


// ================== MESSAGES & TOP BAR ROUTES ==================

// ======== SOCKET.IO ========
io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

// ================== MESSAGES ==================

// --- USER: fetch own messages ---
app.get("/messages", async (req, res) => {
  if (!req.session.user) return res.status(403).json({ success: false, message: "Login required" });
  try {
    const messages = await Message.find({ sender: req.session.user.id }).sort({ createdAt: -1 });
    res.json({ success: true, messages });
  } catch (err) {
    console.error("Error fetching user messages:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// --- USER: send a new message ---
app.post("/messages", async (req, res) => {
  if (!req.session.user) return res.status(403).json({ success: false, message: "Login required" });

  const content = req.body.content?.trim();
  if (!content) return res.status(400).json({ success: false, message: "Message content cannot be empty" });

  try {
    const newMessage = await Message.create({
      sender: req.session.user.id,
      content,
      status: "Pending",
    });

    io.emit("newMessage", {
      _id: newMessage._id,
      name: req.session.user.name,
      email: req.session.user.email,
      text: newMessage.content,
      status: newMessage.status,
    });

    res.json({ success: true, message: newMessage });
  } catch (err) {
    console.error("Message creation failed:", err);
    res.status(500).json({ success: false, message: "Failed to send message" });
  }
});

// --- ADMIN: fetch all messages ---
app.get("/admin/messages/json", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") 
    return res.status(403).json({ success: false, message: "Access denied" });

  try {
    const messages = await Message.find()
      .populate("sender", "name email")
      .sort({ createdAt: -1 });

    res.json(messages.map(m => ({
      _id: m._id,
      name: m.sender?.name || "Unknown",
      email: m.sender?.email || "Unknown",
      text: m.content,
      status: m.status,
      reply: m.reply || null,
      createdAt: m.createdAt,
    })));
  } catch (err) {
    console.error("Error fetching messages:", err);
    res.status(500).json({ success: false, message: "Failed to load messages" });
  }
});

// --- ADMIN: reply to a message ---
app.post("/admin/messages/reply/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ success: false, message: "Access denied" });

  try {
    const { reply } = req.body;
    const message = await Message.findById(req.params.id);
    if (!message) return res.status(404).json({ success: false, message: "Message not found" });

    message.reply = reply;
    message.status = "Replied";
    await message.save();

    io.emit("messageReplied", message);
    res.json({ success: true, message });
  } catch (err) {
    console.error("Error replying to message:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// --- ADMIN: delete a message ---
app.delete("/admin/messages/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ success: false, message: "Access denied" });

  try {
    const message = await Message.findByIdAndDelete(req.params.id);
    if (!message) return res.status(404).json({ success: false, message: "Message not found" });

    io.emit("messageDeleted", message._id);
    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting message:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});


// ================== TOP BAR MESSAGES ==================
// --- ADMIN: create/update top bar message ---
app.post("/admin/top-bar", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ success: false, message: "Access denied" });

  const { id, content, order, active } = req.body;

  try {
    let message;
    if (id) {
      message = await TopBarMessage.findByIdAndUpdate(
        id,
        { content, order, active },
        { new: true }
      );
    } else {
      message = await TopBarMessage.create({ content, order, active });
    }

    io.emit("topBarUpdate"); //  unified event
    res.json({ success: true, message });
  } catch (err) {
    console.error("Error saving top bar message:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// --- ADMIN: delete top bar message ---
app.delete("/admin/top-bar/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ success: false, message: "Access denied" });

  try {
    const deletedMessage = await TopBarMessage.findByIdAndDelete(req.params.id);
    if (!deletedMessage)
      return res.status(404).json({ success: false, message: "Message not found" });

    io.emit("topBarUpdate"); // 🔄 same event for delete
    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting top bar message:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});
// --- ADMIN: get all top bar messages as JSON ---
app.get("/admin/top-bar/json", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ success: false, message: "Access denied" });

  try {
    const messages = await TopBarMessage.find().sort({ order: 1 });
    res.json(messages);
  } catch (err) {
    console.error("Error fetching top bar messages:", err);
    res.status(500).json([]);
  }
});
// --- USER: fetch active top bar messages ---
app.get("/top-bar/active", async (req, res) => {
  try {
    const messages = await TopBarMessage.find({ active: true }).sort({ order: 1 });
    res.json({ success: true, messages });
  } catch (err) {
    console.error("Error fetching active top bar messages:", err);
    res.status(500).json({ success: false, messages: [] });
  }
});


// ================== USER PROFILE ==================

// Render profile page
app.get("/profile", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  try {
    const user = await User.findById(req.session.user.id);
    if (!user) return res.status(404).send("User not found");
    res.render("profile", { user, title: "Profile" });
  } catch (err) {
    console.error("Error loading profile:", err);
    res.status(500).send("Failed to load profile");
  }
});

// Update profile (with Cloudinary upload)
app.post("/profile/update", upload.single("image"), async (req, res) => {
  if (!req.session.user) return res.status(403).send("Login required");

  const { name, phone, studentId } = req.body;

  try {
    const updateData = { name, phone, studentId };

    // If a new image is uploaded
    if (req.file) {
      updateData.image = req.file.path;       // Cloudinary secure URL
      updateData.imageId = req.file.filename; // Cloudinary public_id
    }

    await User.findByIdAndUpdate(req.session.user.id, updateData, { new: true });

    res.redirect("/profile");
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).send("Failed to update profile");
  }
});

// Remove profile image
app.get("/profile/remove-image", async (req, res) => {
  if (!req.session.user) return res.status(403).send("Login required");

  try {
    const user = await User.findById(req.session.user.id);

    if (!user) return res.status(404).send("User not found");

    // Delete from Cloudinary if image exists
    if (user.imageId) {
      await cloudinary.uploader.destroy(user.imageId);
    }

    // Reset image fields in DB
    user.image = null;
    user.imageId = null;
    await user.save();

    res.redirect("/profile");
  } catch (err) {
    console.error("Error removing profile image:", err);
    res.status(500).send("Failed to remove profile image");
  }
});



// ================== OTHER PAGES ==================
const pages = ["user","signup","login","reset-password","gaming","loans","shop","blog","contact","about","privacy-policy","terms","profile","home","whatscoming","refund-policy","terms"];
pages.forEach(page => app.get("/"+page, (req,res)=>res.render(page)));

// ================== START SERVER ==================
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
});