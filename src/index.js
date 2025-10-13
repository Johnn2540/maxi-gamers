// ================== ENVIRONMENT VARIABLES ==================
require("dotenv").config();

// ================== SERVER & CORE MODULES ==================
const express = require("express");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");
const cookieParser = require("cookie-parser");

// ================== AUTH & SECURITY ==================
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const crypto = require("crypto");
const session = require("express-session");
const MongoStore = require("connect-mongo");

// ================== TEMPLATE ENGINE ==================
const hbs = require("hbs");

// ================== FILE UPLOAD & CLOUD ==================
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

// ================== EMAIL ==================
const nodemailer = require("nodemailer");

// ================== DATABASE ==================
const { connectDB, User, Product, Leaderboard, Booking, TopBarMessage, Loan, Message } = require("./mongodb");

// ================== INITIALIZE DATABASE ==================
connectDB();

// ================== APP & SERVER ==================
const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

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

// ================== MIDDLEWARE ==================
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ================== SESSION CONFIG ==================
app.use(
  session({
    name: "connect.sid",
    secret: process.env.SESSION_SECRET || "yourSecretKey",
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
      ttl: 7 * 24 * 60 * 60,
      autoRemove: "interval",
      autoRemoveInterval: 10,
    }),
  })
);

// ================== PASSPORT CONFIGURATION ==================
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value?.toLowerCase().trim();
        const image = profile.photos?.[0]?.value;
        const name = profile.displayName;

        // First, try to find user by googleId
        let user = await User.findOne({ googleId: profile.id });

        if (user) {
          // Update image if missing
          if (!user.image && image) user.image = image;
          if (!user.active) user.active = true;
          await user.save();
          return done(null, user);
        }

        // If not found by googleId, try by email
        user = await User.findOne({ email });

        if (user) {
          // Attach googleId to existing email account
          if (!user.googleId) user.googleId = profile.id;
          if (!user.image && image) user.image = image;
          if (!user.active) user.active = true;
          await user.save();
          return done(null, user);
        }

        // Create new user WITHOUT phone (null)
        const newUser = await User.create({
          googleId: profile.id,
          name,
          email,
          image,
          role: "user",
          active: true,
        });

        return done(null, newUser);
      } catch (err) {
        console.error("Google OAuth error:", err);

        // If duplicate key error happens, find existing user by email and merge
        if (err.code === 11000) {
          const duplicateEmail = err.keyValue?.email;
          if (duplicateEmail) {
            const existingUser = await User.findOne({ email: duplicateEmail });
            if (existingUser && !existingUser.googleId) {
              existingUser.googleId = profile.id;
              if (!existingUser.image && profile.photos?.[0]?.value)
                existingUser.image = profile.photos[0].value;
              if (!existingUser.active) existingUser.active = true;
              await existingUser.save();
            }
            return done(null, existingUser);
          }
        }

        return done(err, null);
      }
    }
  )
);

// ========================
// 🔐 PASSPORT SESSION SETUP
// ========================

// Serialize user into session
passport.serializeUser((user, done) => {
  try {
    if (!user || !user.id) {
      console.error("⚠️ SerializeUser: Missing user or user.id");
      return done(new Error("Invalid user data"));
    }
    done(null, user.id);
  } catch (err) {
    console.error("🔴 SerializeUser error:", err);
    done(err, null);
  }
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
    if (!id) {
      console.error("⚠️ DeserializeUser: Missing user ID");
      return done(new Error("No user ID provided"), null);
    }

    const user = await User.findById(id).lean();
    if (!user) {
      console.error("⚠️ DeserializeUser: User not found:", id);
      return done(null, false);
    }

    done(null, user);
  } catch (err) {
    console.error("🔴 DeserializeUser error:", err);
    done(err, null);
  }
});

// Initialize Passport middleware
app.use(passport.initialize());
app.use(passport.session());

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
  
  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

// ================== AUTH MIDDLEWARE ==================
async function ensureAuthenticated(req, res, next) {
  try {
    if (!req.session.user) {
      const token = req.cookies?.rememberMeToken;
      if (token) {
        const user = await User.findOne({ rememberToken: token });
        if (user) {
          req.session.user = { id: user._id, name: user.name, role: (user.role || "user").toLowerCase() };
          req.session.lastActivity = Date.now();
        } else {
          res.clearCookie("rememberMeToken");
          return res.redirect("/login");
        }
      } else {
        return res.redirect("/login");
      }
    }

    const now = Date.now();
    const TIMEOUT_LIMIT = 30 * 60 * 1000;
    if (req.session.lastActivity && now - req.session.lastActivity > TIMEOUT_LIMIT) {
      req.session.destroy(() => {
        res.clearCookie("rememberMeToken");
        res.redirect(`/login?flash=${encodeURIComponent("Session expired. Please log in again.")}&type=info`);
      });
      return;
    }
    req.session.lastActivity = now;

    const user = await User.findById(req.session.user.id);
    if (!user) {
      req.session.destroy(() => res.redirect("/login"));
      return;
    }

    const role = (user.role || "").toLowerCase();
    if (role !== "admin" && !user.active) {
      req.session.destroy(() =>
        res.status(403).send("Your account is suspended or pending verification.")
      );
      return;
    }

    req.user = user;
    res.locals.user = user;

    if (["/", "/dashboard"].includes(req.path)) {
      return res.redirect(role === "admin" ? "/admin" : "/user");
    }

    next();
  } catch (err) {
    console.error("🔴 Auth check error:", err);
    res.status(500).send("Internal server error");
  }
}

function requireRole(role) {
  return (req, res, next) => {
    const userRole = (req.user?.role || "").toLowerCase();
    if (userRole !== role.toLowerCase()) return res.status(403).send("Access denied.");
    next();
  };
}

function requireAdmin(req, res, next) {
  const userRole = (req.user?.role || "").toLowerCase();
  if (userRole !== "admin") return res.status(403).send("Access denied. Admins only.");
  next();
}

async function handleRememberMe(user, res, remember) {
  if (remember) {
    const token = crypto.randomBytes(32).toString("hex");
    user.rememberToken = token;
    await user.save();

    res.cookie("rememberMeToken", token, {
      maxAge: 30 * 24 * 60 * 60 * 1000,
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

// ================== HELPER FUNCTIONS ==================
function handleSignupError(req, res, message, type = "error", redirectPath = "/signup") {
  if (req.headers.accept?.includes("application/json")) {
    return res.status(400).json({ success: false, message });
  }
  return res.redirect(`${redirectPath}?flash=${encodeURIComponent(message)}&type=${type}`);
}

function handleLoginError(req, res, message, type = "error") {
  if (req.headers.accept?.includes("application/json")) {
    return res.status(401).json({ success: false, message });
  }
  return res.redirect(`/login?flash=${encodeURIComponent(message)}&type=${type}`);
}

function handleFlashRedirect(res, path, message, type = "error") {
  return res.redirect(`${path}?flash=${encodeURIComponent(message)}&type=${type}`);
}

// ================== PAGES CONFIGURATION ==================
const pages = [
  "user", "signup", "login", "reset-password", "gaming", "loans", 
  "shop", "blog", "contact", "about", "privacy-policy", "terms", 
  "profile", "whatscoming", "refund-policy"
];

// ================== STATIC PAGE ROUTES ==================
pages.forEach(page => {
  app.get(`/${page}`, (req, res) => {
    if (['user', 'profile', 'loans', 'gaming'].includes(page)) {
      return ensureAuthenticated(req, res, () => {
        res.render(page, { 
          user: req.session.user,
          title: page.charAt(0).toUpperCase() + page.slice(1)
        });
      });
    }
    res.render(page, { 
      user: req.session.user,
      title: page.charAt(0).toUpperCase() + page.slice(1)
    });
  });
});

// ================== MAIN ROUTES ==================

// --------- HOME ---------
app.get("/", async (req, res) => {
  try {
    const saleProducts = await Product.find({ onSale: true }).limit(6);
    res.render("home", { 
      saleProducts,
      user: req.session.user,
      title: "Home"
    });
  } catch (err) {
    res.status(500).send("Error loading products");
  }
});

// --------- ADMIN DASHBOARD ---------
app.get("/admin", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const [users, products, leaderboard] = await Promise.all([
      User.find().sort({ createdAt: -1 }),
      Product.find(),
      Leaderboard.find().sort({ score: -1 }),
    ]);
    res.render("admin", { 
      users, 
      products, 
      leaderboard,
      user: req.session.user,
      title: "Admin Dashboard"
    });
  } catch (err) {
    res.status(500).send("Error loading admin panel: " + err.message);
  }
});

// ================== AUTH ROUTES ==================

// Google OAuth
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  async (req, res) => {
    try {
      const normalizedRole = (req.user.role || "user").toLowerCase();
      
      req.session.user = {
        id: req.user._id,
        name: req.user.name,
        role: normalizedRole,
      };
      req.session.lastActivity = Date.now();

      if (normalizedRole === "admin") {
        return res.redirect("/admin");
      } else {
        return res.redirect("/user");
      }
    } catch (err) {
      console.error("🔴 Google auth callback error:", err);
      return res.redirect("/login?flash=" + encodeURIComponent("Login failed. Please try again."));
    }
  }
);

app.get("/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie("rememberMeToken");
      res.redirect("/");
    });
  });
});

// ================== USER AUTH ROUTES ==================

// ====== SIGNUP ROUTE ======
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password, studentId } = req.body;

    // Sanitize user input
    const sanitizedEmail = email?.toLowerCase().trim();
    const sanitizedName = name?.trim();
    const sanitizedPhone = phone?.trim();

    // Check required fields
    if (!sanitizedName || !sanitizedEmail || !sanitizedPhone || !password) {
      return handleSignupError(req, res, "All required fields must be filled.", "error");
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitizedEmail)) {
      return handleSignupError(req, res, "Invalid email format.", "error");
    }

    // Validate password: at least 6 characters, includes letters & numbers
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
    if (!passwordRegex.test(password)) {
      return handleSignupError(
        req,
        res,
        "Password must be at least 6 characters long and include at least one letter and one number.",
        "error"
      );
    }

    // Check if user already exists by email or phone
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

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user in DB
    const user = await User.create({
      name: sanitizedName,
      email: sanitizedEmail,
      phone: sanitizedPhone,
      password: hashedPassword,
      studentId,
      role: "user", // Default role
      active: true, // New users are active by default
      createdAt: new Date(),
    });

    // Initialize session for the newly signed-up user
    req.session.user = {
      id: user._id,
      name: user.name,
      role: user.role,
    };

    console.log(`🟢 New user registered: ${user.email}`);

    // Redirect new user to /user dashboard
    return res.redirect("/user");
  } catch (err) {
    console.error("Signup error:", err);

    // Handle MongoDB duplicate key errors
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

    // Fallback error
    return handleSignupError(
      req,
      res,
      "An unexpected error occurred during signup. Please try again.",
      "error"
    );
  }
});

// ====== LOGIN ROUTE (Updated) ======
app.post("/login", async (req, res) => {
  try {
    const { email, password, remember } = req.body;

    const sanitizedEmail = email?.toLowerCase().trim();

    // Validate required fields
    if (!sanitizedEmail || !password) {
      return handleLoginError(req, res, "Email and password are required.");
    }

    // Find user by email
    const user = await User.findOne({ email: sanitizedEmail });
    if (!user) {
      return handleLoginError(req, res, "Invalid email or password.");
    }

    // Compare provided password with hashed password
    const isMatch = await bcrypt.compare(password, user.password || "");
    if (!isMatch) {
      return handleLoginError(req, res, "Invalid email or password.");
    }

    // Prevent inactive users (except admins)
    const role = (user.role || "").toLowerCase();
    if (role !== "admin" && !user.active) {
      return handleLoginError(
        req,
        res,
        "Your account is inactive or suspended. Please contact support."
      );
    }

    // 🚨 Prevent MongoDB duplicate key (phone: null) crash
    if (user.phone === undefined || user.phone === null) {
      user.phone = undefined; // ensures Mongoose won’t include this field in any update
    }

    // Regenerate session securely
    req.session.regenerate(async (err) => {
      if (err) {
        console.error("Session regeneration error:", err);
        return handleLoginError(req, res, "Login session failed. Try again.");
      }

      // Save user info to session
      req.session.user = {
        id: user._id,
        name: user.name,
        role: user.role,
      };
      req.session.lastActivity = Date.now();

      // Handle "Remember Me" safely
      try {
        if (typeof handleRememberMe === "function") {
          await handleRememberMe(user, res, remember);
        }
      } catch (rememberErr) {
        console.warn("⚠️ Remember Me failed:", rememberErr.message);
      }

      // Redirect based on role
      const redirectUrl = role === "admin" ? "/admin" : "/user";

      // Save session and redirect
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("Session save error:", saveErr);
          return handleLoginError(req, res, "Session save failed. Try again.");
        }

        console.log("✅ User logged in:", user.email, "| Role:", role);

        if (req.headers.accept?.includes("application/json")) {
          return res.json({
            success: true,
            message: "Login successful",
            role,
            redirect: redirectUrl,
          });
        }

        res.redirect(redirectUrl);
      });
    });
  } catch (err) {
    console.error("🔴 Login error:", err);
    return handleLoginError(req, res, "Login failed. Please try again.");
  }
});


// ====== RESET PASSWORD ROUTE ======
app.post("/reset-password", async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;

    // Validate all fields
    if (!email || !newPassword || !confirmPassword) {
      return handleFlashRedirect(res, "/reset-password", "All fields are required.", "error");
    }

    // Check password match
    if (newPassword !== confirmPassword) {
      return handleFlashRedirect(res, "/reset-password", "Passwords do not match.", "error");
    }

    // Validate password format
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
    if (!passwordRegex.test(newPassword)) {
      return handleFlashRedirect(
        res,
        "/reset-password",
        "Password must be at least 6 characters long and include at least one letter and one number.",
        "error"
      );
    }

    // Find user by email
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return handleFlashRedirect(
        res,
        "/reset-password",
        "No account found with that email address.",
        "error"
      );
    }

    // Update password with hashed version
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    return handleFlashRedirect(res, "/login", "Password reset successful. You can now log in.", "success");
  } catch (err) {
    console.error("🔴 Reset password error:", err);
    return handleFlashRedirect(res, "/reset-password", "Error resetting password. Please try again.", "error");
  }
});

// ====== CHECK USER EXISTENCE ROUTE ======
app.post("/check-user", async (req, res) => {
  try {
    const { email, phone } = req.body;

    // Must provide either email or phone
    if (!email && !phone) {
      return res.status(400).json({
        success: false,
        exists: false,
        message: "Please provide an email or phone number.",
      });
    }

    // Build query dynamically
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

    // Check if user exists
    const user = await User.findOne({ $or: query });

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


// ================== ADMIN USER ROUTES ==================

app.get("/admin/users/json", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

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

app.post("/admin/users/delete/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/admin/users/edit/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).lean();
    if (!user) return res.status(404).send("User not found");

    res.render("admin/edit-user", { user, title: "Edit User" });
  } catch (err) {
    console.error("Error loading edit page:", err);
    res.status(500).send("Server error");
  }
});

app.post("/admin/users/update/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const { name, email, role } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      { name, email, role },
      { new: true }
    );

    if (!updatedUser) return res.status(404).send("User not found");

    res.redirect("/admin");
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).send("Failed to update user");
  }
});

// ================== PRODUCT ROUTES =================

app.get("/admin/products/json", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const products = await Product.find();

    const formattedProducts = products.map(p => {
      const obj = p.toObject();

      // If "images" is missing but an old single image exists (e.g., mainImage)
      if ((!obj.images || obj.images.length === 0) && obj.mainImage) {
        obj.images = [obj.mainImage];
      }

      // Always set mainImage to the first image
      obj.mainImage = obj.images?.[0] || null;

      return obj;
    });

    res.json(formattedProducts);
  } catch (err) {
    console.error("Error loading admin products:", err);
    res.status(500).json({ success: false, message: "Failed to load products" });
  }
});

// =================== PUBLIC PRODUCT JSON (Shop) ===================
app.get("/products/json", async (req, res) => {
  try {
    const products = await Product.find();

    const productsWithPath = products.map(p => ({
      ...p.toObject(),

      //  Fallback: if "images" array is empty, use mainImage instead
      images: (p.images && p.images.length > 0)
        ? p.images
        : (p.mainImage ? [p.mainImage] : []),

      //  Always ensure mainImage exists for UI display
      mainImage: p.mainImage || (p.images?.[0] || null)
    }));

    res.json(productsWithPath);
  } catch (err) {
    console.error(" Failed to fetch products:", err);
    res.status(500).json({ success: false, message: "Failed to fetch products" });
  }
});


// ================== ADD PRODUCT (Up to 4 Images) ==================
app.post(
  "/admin/products",
  upload.array("images", 4),
  ensureAuthenticated,
  requireAdmin,
  async (req, res) => {
    try {
      const { title, marketPrice, salePrice, description, onSale } = req.body;
      let imageUrls = [];

      // Require at least 1 image
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ success: false, message: "At least one image is required." });
      }

      // Upload all images to Cloudinary
      for (const file of req.files) {
        const result = await cloudinary.uploader.upload(file.path, { folder: "products" });
        imageUrls.push(result.secure_url);
      }

      // Set main image as first image
      const mainImage = imageUrls[0];

      const newProduct = await Product.create({
        title,
        marketPrice,
        salePrice,
        description,
        onSale: onSale === "on" || onSale === "true",
        images: imageUrls,
        mainImage
      });

      io.emit("newProduct", newProduct);
      res.json({ success: true, product: newProduct });
    } catch (err) {
      console.error("Error adding product:", err);
      res.status(500).json({ success: false, message: err.message });
    }
  }
);


// ================== EDIT PRODUCT (Up to 4 Images) ==================
app.post(
  "/admin/products/edit/:id",
  upload.array("images", 4),
  ensureAuthenticated,
  requireAdmin,
  async (req, res) => {
    try {
      const { title, marketPrice, salePrice, description, onSale } = req.body;
      const product = await Product.findById(req.params.id);
      if (!product)
        return res.status(404).json({ success: false, message: "Product not found" });

      // If new images uploaded, replace the old ones
      if (req.files && req.files.length > 0) {
        const uploadedImages = [];
        for (const file of req.files) {
          const result = await cloudinary.uploader.upload(file.path, { folder: "products" });
          uploadedImages.push(result.secure_url);
        }
        product.images = uploadedImages;
        product.mainImage = uploadedImages[0]; // update main image as first
      }

      Object.assign(product, {
        title,
        marketPrice,
        salePrice,
        description,
        onSale: onSale === "on" || onSale === "true"
      });

      await product.save();

      io.emit("updateProduct", product);
      res.json({ success: true, product });
    } catch (err) {
      console.error("Error editing product:", err);
      res.status(500).json({ success: false, message: err.message });
    }
  }
);


// ================== DELETE PRODUCT ==================
app.post("/admin/products/delete/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ success: false, message: "Product not found" });
    io.emit("deleteProduct", product._id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// ================== LEADERBOARD ROUTES ==================

app.get("/top-leaderboard", async (req, res) => {
  try {
    const topPlayers = await Leaderboard.find().sort({ score: -1 }).limit(10);
    res.json(topPlayers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/admin/leaderboard", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const { player, score } = req.body;
    if (!player || score == null) {
      return res.json({ success: false, message: "Player and score required" });
    }

    const newPlayer = await Leaderboard.create({ player, score });
    io.emit("leaderboardUpdate", newPlayer);

    res.json({ success: true, entry: newPlayer });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.put("/admin/leaderboard/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const { player, score } = req.body;
    await Leaderboard.findByIdAndUpdate(req.params.id, { player, score });
    io.emit("leaderboardUpdate");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete("/admin/leaderboard/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    await Leaderboard.findByIdAndDelete(req.params.id);
    io.emit("leaderboardUpdate");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ================== LOAN ROUTES ==================

// Get user loans (page)
app.get("/loans", ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user?._id || req.session.user?.id;
    if (!userId) return res.status(401).send("Not logged in");

    const loans = await Loan.find({ user: userId }).sort({ createdAt: -1 });
    res.render("loans", { 
      loans,
      user: req.session.user,
      title: "My Loans"
    });
  } catch (err) {
    console.error("Error loading user loans:", err);
    res.status(500).send("Failed to load loans");
  }
});

// Submit a new loan
app.post("/loans", ensureAuthenticated, upload.single("itemImage"), async (req, res) => {
  try {
    const userId = req.session.user?._id || req.session.user?.id;
    if (!userId) return res.status(401).send("Not logged in");

    let imageUrl = null;
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, { folder: "loans" });
      imageUrl = result.secure_url;
    }

    const loan = await Loan.create({
      user: userId,
      itemImage: imageUrl,
      description: req.body.description,
      itemValue: req.body.itemValue,
      loanAmount: req.body.loanAmount,
      loanPeriod: req.body.loanPeriod,
      status: "Pending",
    });

    io.emit("loanCreated", loan);

    if (req.headers.accept?.includes("application/json")) {
      return res.json({ success: true, loan });
    }

    res.redirect("/loans");
  } catch (err) {
    console.error("Loan submission error:", err);
    res.status(500).send("Failed to submit loan");
  }
});

// Get user loans as JSON
app.get("/loans/list", ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user?._id || req.session.user?.id;
    if (!userId) return res.status(401).json([]);

    const loans = await Loan.find({ user: userId }).sort({ createdAt: -1 });
    res.json(loans);
  } catch (err) {
    console.error("Error fetching user loans:", err);
    res.status(500).json([]);
  }
});

// Admin view loans (page)
app.get("/admin/loans", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const loans = await Loan.find().populate("user", "name email").sort({ createdAt: -1 });
    res.render("admin-loans", { 
      loans,
      user: req.session.user,
      title: "Admin Loans"
    });
  } catch (err) {
    console.error("Error loading admin loans:", err);
    res.status(500).send("Failed to load loans");
  }
});

// Admin loans JSON
app.get("/admin/loans/json", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const loans = await Loan.find().populate("user", "name email").sort({ createdAt: -1 });
    res.json(loans);
  } catch (err) {
    console.error("Error fetching admin loans:", err);
    res.status(500).json([]);
  }
});

// Update loan status (admin)
app.post("/admin/loans/:id/status", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const loan = await Loan.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).populate("user", "name email");

    if (!loan) return res.status(404).json({ success: false, message: "Loan not found" });

    io.emit("loanUpdated", loan);
    res.json({ success: true, loan });
  } catch (err) {
    console.error("Loan update error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});


// ================== GAMING BOOKINGS ==================

app.post("/gaming/book", ensureAuthenticated, async (req, res) => {
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

    const populatedBooking = await Booking.findById(booking._id).populate("user", "name email");
    io.emit("newBooking", { ...populatedBooking.toObject(), isNew: true });

    res.json({ success: true, booking: populatedBooking });
  } catch (err) {
    console.error("Error creating booking:", err);
    res.status(500).json({ success: false, message: "Failed to create booking" });
  }
});

app.post("/admin/bookings/update/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
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

    const populatedBooking = await Booking.findById(booking._id).populate("user", "name email");
    io.emit("updateBooking", populatedBooking);
    res.json({ success: true, booking: populatedBooking });
  } catch (err) {
    console.error("Error updating booking:", err);
    res.status(500).json({ success: false, message: "Failed to update booking" });
  }
});

app.get("/admin/bookings/json", ensureAuthenticated, requireAdmin, async (req, res) => {
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

app.get("/gaming/bookings/json", ensureAuthenticated, async (req, res) => {
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

// ================== MESSAGES ==================

app.get("/messages", ensureAuthenticated, async (req, res) => {
  try {
    const messages = await Message.find({ sender: req.session.user.id }).sort({ createdAt: -1 });
    res.json({ success: true, messages });
  } catch (err) {
    console.error("Error fetching user messages:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/messages", ensureAuthenticated, async (req, res) => {
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

app.get("/admin/messages/json", ensureAuthenticated, requireAdmin, async (req, res) => {
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

app.post("/admin/messages/reply/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
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

app.delete("/admin/messages/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
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

app.post("/admin/top-bar", ensureAuthenticated, requireAdmin, async (req, res) => {
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

    io.emit("topBarUpdate");
    res.json({ success: true, message });
  } catch (err) {
    console.error("Error saving top bar message:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete("/admin/top-bar/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const deletedMessage = await TopBarMessage.findByIdAndDelete(req.params.id);
    if (!deletedMessage) return res.status(404).json({ success: false, message: "Message not found" });

    io.emit("topBarUpdate");
    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting top bar message:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/admin/top-bar/json", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const messages = await TopBarMessage.find().sort({ order: 1 });
    res.json(messages);
  } catch (err) {
    console.error("Error fetching top bar messages:", err);
    res.status(500).json([]);
  }
});

app.get("/top-bar/active", async (req, res) => {
  try {
    const messages = await TopBarMessage.find({ active: true }).sort({ order: 1 });
    res.json({ success: true, messages });
  } catch (err) {
    console.error("Error fetching active top bar messages:", err);
    res.status(500).json({ success: false, messages: [] });
  }
});

// ================== USER PROFILE ROUTES ==================

// GET profile page
app.get("/profile", ensureAuthenticated, async (req, res) => {
  try {
    if (!req.session.user?.id) {
      console.error("No user session found");
      return res.redirect("/login");
    }

    const user = await User.findById(req.session.user.id);
    if (!user) {
      console.error("User not found in DB");
      return res.status(404).send("User not found");
    }

    res.render("profile", {
      user,
      title: "Profile",
      currentUser: req.session.user,
      flash: req.session.flash || null,
    });

    // Clear flash after rendering
    req.session.flash = null;
  } catch (err) {
    console.error("Error loading profile:", err);
    res.status(500).send("Failed to load profile");
  }
});

// POST update profile (name, phone, studentId, and profile image)
app.post("/profile/update", ensureAuthenticated, upload.single("image"), async (req, res) => {
  const { name, phone, studentId } = req.body;

  try {
    if (!req.session.user?.id) {
      req.session.flash = { type: "error", message: "Session expired. Please login again." };
      return res.redirect("/login");
    }

    const updateData = { name, phone, studentId };

    if (req.file) {
      // Upload new profile image to Cloudinary
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: "profiles"
      });

      // Remove old image from Cloudinary if exists
      const user = await User.findById(req.session.user.id);
      if (user?.imageId) {
        try {
          await cloudinary.uploader.destroy(user.imageId);
        } catch (destroyErr) {
          console.warn("Old profile image could not be removed:", destroyErr.message);
        }
      }

      // Save new image URL and Cloudinary public_id
      updateData.image = result.secure_url;
      updateData.imageId = result.public_id;
    }

    // Update user document
    await User.findByIdAndUpdate(req.session.user.id, updateData, { new: true });

    req.session.flash = { type: "success", message: "Profile updated successfully!" };
    res.redirect("/profile");
  } catch (err) {
    console.error("Profile update error:", err);
    req.session.flash = { type: "error", message: "Failed to update profile." };
    res.redirect("/profile");
  }
});

// GET remove profile image
app.get("/profile/remove-image", ensureAuthenticated, async (req, res) => {
  try {
    if (!req.session.user?.id) {
      req.session.flash = { type: "error", message: "Session expired. Please login again." };
      return res.redirect("/login");
    }

    const user = await User.findById(req.session.user.id);
    if (!user) return res.status(404).send("User not found");

    // Delete image from Cloudinary if exists
    if (user.imageId) {
      try {
        await cloudinary.uploader.destroy(user.imageId);
      } catch (destroyErr) {
        console.warn("Failed to remove image from Cloudinary:", destroyErr.message);
      }
    }

    // Reset to default profile image
    user.image = "/images/default-profile.png";
    user.imageId = null;
    await user.save();

    req.session.flash = { type: "success", message: "Profile image removed successfully!" };
    res.redirect("/profile");
  } catch (err) {
    console.error("Error removing profile image:", err);
    req.session.flash = { type: "error", message: "Failed to remove profile image." };
    res.redirect("/profile");
  }
});


// ================== ERROR HANDLING ==================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', { 
    error: process.env.NODE_ENV === 'production' ? {} : err,
    user: req.session.user,
    title: "Error"
  });
});

app.use((req, res) => {
  res.status(404).render('404', { 
    user: req.session.user,
    title: "Page Not Found"
  });
});

// ================== DEBUG ==================
console.log("GOOGLE_CLIENT_ID loaded:", !!process.env.GOOGLE_CLIENT_ID);
console.log("Mongo URI loaded:", !!process.env.MONGO_URI);
console.log("Session Secret loaded:", !!process.env.SESSION_SECRET);
console.log("JWT Secret loaded:", !!process.env.JWT_SECRET);

// ================== START SERVER ==================
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

// ================== EXPORTS ==================
module.exports = {
  ensureAuthenticated,
  requireAdmin,
  requireRole,
  handleRememberMe,
};