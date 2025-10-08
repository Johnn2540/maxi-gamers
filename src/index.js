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
const MongoStore = require("connect-mongo");
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
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
      ttl: 7 * 24 * 60 * 60, // 7 days
    }),
  })
);

// ================== PASSPORT GOOGLE OAUTH ==================
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value?.toLowerCase().trim();
    const image = profile.photos?.[0]?.value;
    const name = profile.displayName;

    //  Step 1: Check for existing user by googleId or email
    let user = await User.findOne({
      $or: [{ googleId: profile.id }, { email }]
    });

    if (user) {
      //  Step 2: Link Google ID if missing
      if (!user.googleId) {
        user.googleId = profile.id;
        if (image && !user.image) user.image = image;
        await user.save();
      }

      //  Ensure the account is active (in case they registered but never verified)
      if (!user.active) {
        user.active = true;
        await user.save();
      }

      return done(null, user);
    }

    //  Step 3: If no user exists, safely create a new one
    user = await User.create({
      googleId: profile.id,
      name,
      email,
      image,
      role: "user",
      active: true,
      createdAt: new Date()
    });

    return done(null, user);
  } catch (err) {
    console.error("Google OAuth error:", err);

    //  Step 4: Handle duplicate key error gracefully (no crash)
    if (err.code === 11000 && err.keyPattern?.email) {
      const existingUser = await User.findOne({ email: profile.emails?.[0]?.value });
      if (existingUser) {
        // Link Google account manually if necessary
        if (!existingUser.googleId) {
          existingUser.googleId = profile.id;
          if (!existingUser.image && profile.photos?.[0]?.value) {
            existingUser.image = profile.photos[0].value;
          }
          await existingUser.save();
        }
        return done(null, existingUser);
      }
    }

    return done(err, null);
  }
}));


// ================== SERIALIZE / DESERIALIZE ==================
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

// ================== AUTH ROUTES ==================

// Step 1: Start Google login
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// Step 2: Google callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Save user in session
    req.session.user = {
      id: req.user._id,
      name: req.user.name,
      role: req.user.role,
    };

    // Redirect based on user role
    if (req.user.role === "admin") {
      return res.redirect("/admin");
    } else {
      return res.redirect("/user");
    }
  }
);

// Step 3: Logout route
app.get("/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy();
    res.redirect("/");
  });
});


// ================== MIDDLEWARE ==================
app.set("trust proxy", 1);
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
 * Ensure the user is authenticated before accessing protected routes
 */
async function ensureAuthenticated(req, res, next) {
  try {
    // 1️⃣ If no active session, check Remember Me cookie
    if (!req.session.user) {
      const token = req.cookies?.rememberMeToken;

      if (token) {
        const user = await User.findOne({ rememberToken: token });
        if (user) {
          req.session.user = { id: user._id, name: user.name, role: user.role };
          req.session.lastActivity = Date.now();
        } else {
          res.clearCookie("rememberMeToken");
          return res.redirect("/login");
        }
      } else {
        return res.redirect("/login");
      }
    }

    // 2️⃣ Session inactivity timeout (30 minutes)
    const now = Date.now();
    const TIMEOUT_LIMIT = 30 * 60 * 1000; // 30 min
    if (req.session.lastActivity && now - req.session.lastActivity > TIMEOUT_LIMIT) {
      req.session.destroy(() => {
        res.clearCookie("rememberMeToken");
        return res.redirect(
          `/login?flash=${encodeURIComponent("Session expired. Please log in again.")}&type=info`
        );
      });
      return;
    }
    req.session.lastActivity = now;

    // 3️⃣ Verify user still exists
    const user = await User.findById(req.session.user.id);
    if (!user) {
      req.session.destroy(() => res.redirect("/login"));
      return;
    }

    // 4️⃣ Check account status for normal users
    const role = (user.role || "").toLowerCase();
    if (role === "user" && !user.active) {
      req.session.destroy(() =>
        res.status(403).send("Your account is suspended or pending verification.")
      );
      return;
    }

    // 5️⃣ Attach user object for downstream routes
    req.user = user;

    // 6️⃣ Smart redirect if visiting root/dashboard
    if (["/", "/dashboard"].includes(req.path)) {
      return res.redirect(role === "admin" ? "/admin" : "/user");
    }

    // ✅ Allow access
    next();
  } catch (err) {
    console.error("🔴 Auth check error:", err);
    res.status(500).send("Internal server error");
  }
}

/**
 * Restrict route to specific user roles (case-insensitive)
 */
function requireRole(role) {
  return (req, res, next) => {
    const userRole = (req.user?.role || "").toLowerCase();
    if (userRole !== role.toLowerCase()) {
      return res.status(403).send("Access denied.");
    }
    next();
  };
}

/**
 * Restrict route to admins only
 */
function requireAdmin(req, res, next) {
  const role = (req.user?.role || "").toLowerCase();
  if (role !== "admin") {
    return res.status(403).send("Access denied. Admins only.");
  }
  next();
}

/**
 * Handle "Remember Me" cookie setup
 */
async function handleRememberMe(user, res, remember) {
  if (remember) {
    const token = crypto.randomBytes(32).toString("hex");
    user.rememberToken = token;
    await user.save();

    res.cookie("rememberMeToken", token, {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
  } else {
    user.rememberToken = null;
    await user.save();
    res.clearCookie("rememberMeToken");
  }
}

// ================== EXPORTS ==================
module.exports = {
  ensureAuthenticated,
  requireAdmin,
  requireRole,
  handleRememberMe,
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

// Middleware to ensure the user is logged in
function ensureAuthenticated(req, res, next) {
  if (!req.session.user) {
    // If AJAX or API request, send JSON error
    if (req.headers.accept?.includes("application/json")) {
      return res.status(403).json({ success: false, message: "Login required" });
    }
    // If browser request, redirect to login
    return res.redirect("/login");
  }
  next();
}

// Render user's loans page (HTML)
app.get("/loans", ensureAuthenticated, async (req, res) => {
  try {
    const loans = await Loan.find({ user: req.session.user.id }).sort({ createdAt: -1 });
    res.render("loans", { loans });
  } catch (err) {
    console.error("Error loading user loans:", err);
    res.status(500).send("Failed to load loans");
  }
});

// Create a new loan (form submission or API)
app.post("/loans", ensureAuthenticated, upload.single("itemImage"), async (req, res) => {
  try {
    const { description, itemValue, loanAmount, loanPeriod } = req.body;

    // Input validation
    if (!description || !itemValue || !loanAmount || !loanPeriod) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const loan = await Loan.create({
      user: req.session.user.id,
      itemImage: req.file ? req.file.path : null, // Cloudinary URL
      description,
      itemValue,
      loanAmount,
      loanPeriod,
      status: "Pending",
    });

    // Notify admins (via Socket.IO)
    io.emit("loanCreated", loan);

    // Handle response types
    if (req.headers.accept?.includes("application/json")) {
      return res.json({ success: true, loan });
    }

    res.redirect("/loans");
  } catch (err) {
    console.error("Loan submission error:", err);
    if (req.headers.accept?.includes("application/json")) {
      return res.status(500).json({ success: false, message: "Server error while creating loan" });
    }
    res.status(500).send("Failed to submit loan");
  }
});

// Fetch user's loans (AJAX or API)
app.get("/loans/list", ensureAuthenticated, async (req, res) => {
  try {
    const loans = await Loan.find({ user: req.session.user.id }).sort({ createdAt: -1 });
    res.json(loans);
  } catch (err) {
    console.error("Error fetching user loans:", err);
    res.status(500).json({ success: false, message: "Failed to load loans" });
  }
});



// ================== ADMIN LOANS ==================

// Middleware to ensure user is logged in and is an admin
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    if (req.headers.accept?.includes("application/json")) {
      return res.status(403).json({ success: false, message: "Admin access required" });
    }
    return res.status(403).send("Access Denied");
  }
  next();
}

// Render Admin Loans Page (HTML)
app.get("/admin/loans", requireAdmin, async (req, res) => {
  try {
    const loans = await Loan.find()
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    res.render("admin-loans", { loans });
  } catch (err) {
    console.error("Error loading admin loans:", err);
    res.status(500).send("Failed to load loans");
  }
});

// Fetch all loans (Admin JSON/AJAX)
app.get("/admin/loans/json", requireAdmin, async (req, res) => {
  try {
    const loans = await Loan.find()
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    res.json({ success: true, loans });
  } catch (err) {
    console.error("Error fetching admin loans:", err);
    res.status(500).json({ success: false, message: "Failed to load loans" });
  }
});

// Admin: Update Loan Status
app.post("/admin/loans/:id/status", requireAdmin, async (req, res) => {
  const { status } = req.body;

  // Validate input
  const validStatuses = ["Pending", "Approved", "Rejected", "Completed"];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ success: false, message: "Invalid loan status" });
  }

  try {
    const loan = await Loan.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).populate("user", "name email");

    if (!loan) {
      return res.status(404).json({ success: false, message: "Loan not found" });
    }

    // Notify connected clients (e.g., admin dashboard + user)
    io.emit("loanUpdated", loan);

    res.json({ success: true, loan });
  } catch (err) {
    console.error("Loan update error:", err);
    res.status(500).json({ success: false, message: "Failed to update loan status" });
  }
});


// ================== USER ROUTES ==================

// ================== USER SIGNUP ==================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password, studentId } = req.body;

    // 1️⃣ Input sanitization
    const sanitizedEmail = email?.toLowerCase().trim();
    const sanitizedName = name?.trim();
    const sanitizedPhone = phone?.trim();

    // 2️⃣ Basic validation
    if (!sanitizedName || !sanitizedEmail || !sanitizedPhone || !password) {
      const msg = "All required fields must be filled.";
      return handleSignupError(req, res, msg, "error");
    }

    // 3️⃣ Email format check
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitizedEmail)) {
      return handleSignupError(req, res, "Invalid email format.", "error");
    }

    // 4️⃣ Password strength check
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
    if (!passwordRegex.test(password)) {
      return handleSignupError(
        req,
        res,
        "Password must be at least 6 characters long and include at least one letter and one number.",
        "error"
      );
    }

    // 5️⃣ Check for existing user (email or phone)
    const existingUser = await User.findOne({
      $or: [{ email: sanitizedEmail }, { phone: sanitizedPhone }],
    });

    if (existingUser) {
      return handleSignupError(
        req,
        res,
        "User already exists. Please login instead.",
        "info",
        "/login"
      );
    }

    // 6️⃣ Hash password securely
    const hashedPassword = await bcrypt.hash(password, 10);

    // 7️⃣ Create user (active immediately)
    const user = await User.create({
      name: sanitizedName,
      email: sanitizedEmail,
      phone: sanitizedPhone,
      password: hashedPassword,
      studentId,
      role: "user",
      active: true,
      createdAt: new Date(),
    });

    // 8️⃣ Auto-login after signup
    req.session.user = {
      id: user._id,
      name: user.name,
      role: user.role,
    };

    console.log(`🟢 New user registered: ${user.email}`);

    // 9️⃣ Redirect to user dashboard
    return res.redirect("/user");
  } catch (err) {
    console.error("Signup error:", err);

    // 10️⃣ Duplicate key (MongoDB 11000 error)
    if (err.code === 11000) {
      if (err.keyPattern?.email) {
        return handleSignupError(
          req,
          res,
          "Email already registered. Please login instead.",
          "info",
          "/login"
        );
      }
      if (err.keyPattern?.phone) {
        return handleSignupError(
          req,
          res,
          "Phone number already registered. Please login instead.",
          "info",
          "/login"
        );
      }
    }

    // 11️⃣ Generic fallback
    return handleSignupError(
      req,
      res,
      "An unexpected error occurred during signup. Please try again.",
      "error"
    );
  }
});

// ================== HELPER FUNCTION ==================
function handleSignupError(req, res, message, type = "error", redirectPath = "/signup") {
  if (req.headers.accept?.includes("application/json")) {
    return res.status(400).json({ success: false, message });
  }
  return res.redirect(
    `${redirectPath}?flash=${encodeURIComponent(message)}&type=${type}`
  );
}


// ================== USER LOGIN ==================
app.post("/login", async (req, res) => {
  try {
    const { email, password, remember } = req.body;

    // 1️⃣ Sanitize & validate
    const sanitizedEmail = email?.toLowerCase().trim();
    if (!sanitizedEmail || !password) {
      return handleLoginError(req, res, "Email and password are required.");
    }

    // 2️⃣ Find user by email
    const user = await User.findOne({ email: sanitizedEmail });
    if (!user) {
      return handleLoginError(req, res, "Invalid email or password.");
    }

    // 3️⃣ Compare password (hashed)
    const isMatch = await bcrypt.compare(password, user.password || "");
    if (!isMatch) {
      return handleLoginError(req, res, "Invalid email or password.");
    }

    // 4️⃣ Check if user is active
    if (!user.active) {
      return handleLoginError(
        req,
        res,
        "Your account is inactive or suspended. Please contact support."
      );
    }

    // 5️⃣ Create session
    req.session.user = {
      id: user._id,
      name: user.name,
      role: user.role,
    };
    req.session.lastActivity = Date.now();

    // 6️⃣ Handle “Remember Me” feature
    await handleRememberMe(user, res, remember);

    // 7️⃣ Redirect or respond based on role
    const role = (user.role || "").toLowerCase();
    const redirectUrl =
      role === "admin"
        ? "/admin"
        : role === "user"
        ? "/user"
        : "/";

    // Support both HTML and JSON login
    if (req.headers.accept?.includes("application/json")) {
      return res.json({
        success: true,
        message: "Login successful",
        role,
        redirect: redirectUrl,
      });
    }

    return res.redirect(redirectUrl);
  } catch (err) {
    console.error("🔴 Login error:", err);
    return handleLoginError(req, res, "Login failed. Please try again.");
  }
});

// ================== HELPER FUNCTION ==================
function handleLoginError(req, res, message, type = "error") {
  if (req.headers.accept?.includes("application/json")) {
    return res.status(401).json({ success: false, message });
  }
  return res.redirect(
    `/login?flash=${encodeURIComponent(message)}&type=${type}`
  );
}


// ================== RESET PASSWORD ==================
app.post("/reset-password", async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;

    // 1️⃣ Validate inputs
    if (!email || !newPassword || !confirmPassword) {
      return handleFlashRedirect(
        res,
        "/reset-password",
        "All fields are required.",
        "error"
      );
    }

    // 2️⃣ Password confirmation
    if (newPassword !== confirmPassword) {
      return handleFlashRedirect(
        res,
        "/reset-password",
        "Passwords do not match.",
        "error"
      );
    }

    // 3️⃣ Password strength validation
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
    if (!passwordRegex.test(newPassword)) {
      return handleFlashRedirect(
        res,
        "/reset-password",
        "Password must be at least 6 characters long and include at least one letter and one number.",
        "error"
      );
    }

    // 4️⃣ Find user
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return handleFlashRedirect(
        res,
        "/reset-password",
        "No account found with that email address.",
        "error"
      );
    }

    // 5️⃣ Hash and update password
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    // 6️⃣ Redirect to login
    return handleFlashRedirect(
      res,
      "/login",
      "Password reset successful. You can now log in.",
      "success"
    );
  } catch (err) {
    console.error("🔴 Reset password error:", err);
    return handleFlashRedirect(
      res,
      "/reset-password",
      "Error resetting password. Please try again.",
      "error"
    );
  }
});

// ================== CHECK USER (AJAX) ==================
app.post("/check-user", async (req, res) => {
  try {
    const { email, phone } = req.body;

    // 1️⃣ Validate input
    if (!email && !phone) {
      return res.status(400).json({
        success: false,
        exists: false,
        message: "Please provide an email or phone number.",
      });
    }

    // 2️⃣ Build query dynamically
    const query = [];
    if (typeof email === "string" && email.trim()) {
      query.push({ email: email.toLowerCase().trim() });
    }
    if (typeof phone === "string" && phone.trim()) {
      query.push({ phone: phone.trim() });
    }

    if (!query.length) {
      return res.status(400).json({
        success: false,
        exists: false,
        message: "Invalid email or phone format.",
      });
    }

    // 3️⃣ Search for user
    const user = await User.findOne({ $or: query });

    // 4️⃣ Respond
    if (user) {
      return res.json({
        success: true,
        exists: true,
        message: "A user with this email or phone already exists.",
      });
    }

    return res.json({
      success: true,
      exists: false,
      message: "No matching user found.",
    });
  } catch (err) {
    console.error("🔴 Check-user error:", err);
    return res.status(500).json({
      success: false,
      exists: false,
      message: "Internal server error.",
    });
  }
});



// ================== GOOGLE OAUTH ROUTES ==================
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    req.session.user = {
      id: req.user._id,
      name: req.user.name,
      role: req.user.role,
    };
    const redirectMap = { admin: "/admin", user: "/user" };
    res.redirect(redirectMap[(req.user.role || "").toLowerCase()] || "/");
  }
);

// ================== GAMING BOOKINGS ==================

// ✅ Middleware for auth checks
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(403).json({ success: false, message: "Login required" });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Access denied" });
  }
  next();
}

// ✅ Create a new booking (User)
app.post("/gaming/book", requireLogin, async (req, res) => {
  try {
    const { game, console, date, timeSlot } = req.body;

    if (!game || !console || !date || !timeSlot) {
      return res.status(400).json({ success: false, message: "Missing required fields." });
    }

    const booking = await Booking.create({
      user: req.session.user.id,
      game,
      console,
      date,
      timeSlot
    });

    const populatedBooking = await Booking.findById(booking._id)
      .populate("user", "name email");

    io.emit("newBooking", { ...populatedBooking.toObject(), isNew: true });

    res.json({ success: true, booking: populatedBooking });
  } catch (err) {
    console.error("Error creating booking:", err);
    res.status(500).json({ success: false, message: "Failed to create booking" });
  }
});

// ✅ Update booking status (Admin)
app.post("/admin/bookings/update/:id", requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!status) {
      return res.status(400).json({ success: false, message: "Status is required." });
    }

    const booking = await Booking.findById(req.params.id);
    if (!booking) {
      return res.status(404).json({ success: false, message: "Booking not found" });
    }

    booking.status = status;
    await booking.save();

    const populatedBooking = await Booking.findById(booking._id)
      .populate("user", "name email");

    io.emit("updateBooking", populatedBooking);
    res.json({ success: true, booking: populatedBooking });
  } catch (err) {
    console.error("Error updating booking:", err);
    res.status(500).json({ success: false, message: "Failed to update booking" });
  }
});

// ✅ Fetch all bookings (Admin)
app.get("/admin/bookings/json", requireAdmin, async (req, res) => {
  try {
    const bookings = await Booking.find()
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    const now = new Date();
    const bookingsWithFlag = bookings.map(b => {
      const bookingObj = b.toObject();
      bookingObj.user ||= { name: "Unknown User", email: "N/A" };
      const createdAt = b.createdAt instanceof Date ? b.createdAt : null;
      bookingObj.isNew = createdAt ? (now - createdAt) / 1000 < 10 : false;
      bookingObj.createdAt = createdAt;
      return bookingObj;
    });

    res.json(bookingsWithFlag);
  } catch (err) {
    console.error("Error fetching admin bookings:", err);
    res.status(500).json([]);
  }
});

// ✅ Fetch logged-in user’s bookings
app.get("/gaming/bookings/json", requireLogin, async (req, res) => {
  try {
    const bookings = await Booking.find({ user: req.session.user.id })
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    const safeBookings = bookings.map(b => {
      const bookingObj = b.toObject();
      bookingObj.user ||= { name: "Unknown User", email: "N/A" };
      return bookingObj;
    });

    res.json(safeBookings);
  } catch (err) {
    console.error("Error fetching user bookings:", err);
    res.status(500).json([]);
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
  console.log(`Server running on port ${PORT}`);
});
