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

// ================== HELPER FUNCTIONS ==================
function handleSignupError(req, res, message, type = "error", redirectTo = "/signup") {
  if (req.headers.accept?.includes("application/json")) {
    return res.status(400).json({ success: false, message, type });
  }
  return res.redirect(`${redirectTo}?flash=${encodeURIComponent(message)}&type=${type}`);
}

function handleLoginError(req, res, message) {
  if (req.headers.accept?.includes("application/json")) {
    return res.status(400).json({ success: false, message });
  }
  return res.redirect(`/login?flash=${encodeURIComponent(message)}&type=error`);
}

function handleFlashRedirect(res, path, message, type) {
  return res.redirect(`${path}?flash=${encodeURIComponent(message)}&type=${type}`);
}

// ================== SAFE HELPERS ==================
async function safeDestroySession(req, res) {
  return new Promise(resolve => {
    try {
      if (req.session) {
        req.session.destroy(err => {
          if (err) console.error("⚠️ Error destroying session:", err.message);
          res.clearCookie("connect.sid", { path: "/" });
          resolve(true);
        });
      } else {
        res.clearCookie("connect.sid", { path: "/" });
        resolve(false);
      }
    } catch (err) {
      console.error("⚠️ safeDestroySession error:", err.message);
      resolve(false);
    }
  });
}

function safeRedirect(res, url) {
  try {
    if (!res.headersSent) res.redirect(url);
  } catch (err) {
    console.error("⚠️ safeRedirect error:", err.message);
  }
}

// ================== AUTH MIDDLEWARE ==================
async function ensureAuthenticated(req, res, next) {
  try {
    let sessionUser = req.session.user;

    // ================== RESTORE FROM REMEMBER ME ==================
    if (!sessionUser && req.cookies?.rememberMeToken) {
      const userFromToken = await User.findOne({ rememberToken: req.cookies.rememberMeToken });

      if (userFromToken) {
        sessionUser = req.session.user = {
          id: userFromToken._id.toString(),
          name: userFromToken.name,
          role: (userFromToken.role || "user").toLowerCase(),
        };
        req.session.lastActivity = Date.now();
        req.session.justLoggedIn = true;

        await req.session.save(); // ✅ Ensure session persisted before continuing
        console.log(`🔁 Session restored from Remember Me for ${userFromToken.email || userFromToken.name}`);
      } else {
        res.clearCookie("rememberMeToken", { path: "/" });
        return safeRedirect(res, "/login");
      }
    }

    // ================== NO SESSION → REDIRECT ==================
    if (!sessionUser) return safeRedirect(res, "/login");

    // ================== SESSION TIMEOUT (30 minutes) ==================
    const now = Date.now();
    const TIMEOUT_LIMIT = 30 * 60 * 1000; // 30 min inactivity timeout

    if (req.session.lastActivity && now - req.session.lastActivity > TIMEOUT_LIMIT) {
      console.warn("⚠️ Session expired for:", sessionUser.name);
      await safeDestroySession(req, res);
      return safeRedirect(
        res,
        `/login?flash=${encodeURIComponent("Session expired. Please log in again.")}&type=info`
      );
    } else {
      req.session.lastActivity = now; // ✅ Update timestamp
      await req.session.save();
    }

    // ================== FETCH USER FROM DATABASE ==================
    const user = await User.findById(sessionUser.id);
    if (!user) {
      await safeDestroySession(req, res);
      return safeRedirect(res, "/login");
    }

    const role = (user.role || "").toLowerCase();

    // ================== BLOCK INACTIVE NON-ADMIN USERS ==================
    if (role !== "admin" && !user.active) {
      await safeDestroySession(req, res);
      return safeRedirect(
        res,
        `/login?flash=${encodeURIComponent("Your account is suspended. Contact admin.")}&type=error`
      );
    }

    // ================== ATTACH USER TO REQ & LOCALS ==================
    req.user = user;
    res.locals.user = {
      ...user.toObject(),
      profilePic: user.profilePic || "https://via.placeholder.com/40",
      username: user.name || "Guest",
    };

    // ================== ONE-TIME REDIRECT AFTER LOGIN ==================
    if (req.session.justLoggedIn) {
      delete req.session.justLoggedIn;
      await req.session.save();
      return safeRedirect(res, role === "admin" ? "/admin" : "/user");
    }

    // ================== ROOT/DASHBOARD AUTO REDIRECT ==================
    if (["/", "/dashboard"].includes(req.path)) {
      return safeRedirect(res, role === "admin" ? "/admin" : "/user");
    }

    next();
  } catch (err) {
    console.error("❌ Authentication error:", err);
    res.status(500).send("Internal server error during authentication.");
  }
}

// ================== ROLE CHECK HELPERS ==================
function requireRole(role) {
  return (req, res, next) => {
    const userRole = (req.user?.role || "").toLowerCase();

    if (userRole !== role.toLowerCase()) {
      console.warn(`🚫 Access denied: ${req.user?.email || "Unknown"} → ${req.originalUrl}`);

      if (req.xhr || req.headers.accept?.includes("application/json")) {
        return res.status(403).json({ error: "Access denied" });
      } else {
        return res.redirect(`/login?flash=${encodeURIComponent("Access denied.")}&type=error`);
      }
    }

    next();
  };
}

function requireAdmin(req, res, next) {
  const userRole = (req.user?.role || "").toLowerCase();

  if (userRole !== "admin") {
    console.warn(`🚫 Non-admin access attempt by: ${req.user?.email || "Unknown"} → ${req.originalUrl}`);

    if (req.xhr || req.headers.accept?.includes("application/json")) {
      return res.status(403).json({ error: "Admins only" });
    } else {
      return res.redirect(`/user?flash=${encodeURIComponent("Admins only.")}&type=error`);
    }
  }

  next();
}

// ================== REMEMBER ME HANDLER ==================
async function handleRememberMe(user, res, remember) {
  try {
    // Ensure user is a Mongoose document
    if (!user.save) {
      const fetchedUser = await User.findById(user._id || user.id);
      if (!fetchedUser) throw new Error("User not found for Remember Me");
      user = fetchedUser;
    }

    if (remember) {
      const token = crypto.randomBytes(32).toString("hex");
      user.rememberToken = token;
      await user.save();

      res.cookie("rememberMeToken", token, {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/",
      });

      console.log(`💾 Remember Me token set for ${user.email || user.name}`);
    } else {
      user.rememberToken = null;
      await user.save();
      res.clearCookie("rememberMeToken", { path: "/" });
      console.log(`🧹 Remember Me token cleared for ${user.email || user.name}`);
    }
  } catch (err) {
    console.error("⚠️ Remember Me handler error:", err);
  }
}


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

// ================== USER AUTH ROUTES ==================

// ====== SIGNUP ROUTE ======
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password, studentId } = req.body;

    // 1️⃣ Sanitize user input
    const sanitizedEmail = email?.toLowerCase().trim();
    const sanitizedName = name?.trim();
    const sanitizedPhone = phone?.trim();

    // 2️⃣ Check required fields
    if (!sanitizedName || !sanitizedEmail || !sanitizedPhone || !password) {
      return handleSignupError(req, res, "All required fields must be filled.", "error");
    }

    // 3️⃣ Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitizedEmail)) {
      return handleSignupError(req, res, "Invalid email format.", "error");
    }

    // 4️⃣ Validate password (min 6 chars, at least 1 letter & 1 number)
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
    if (!passwordRegex.test(password)) {
      return handleSignupError(
        req,
        res,
        "Password must be at least 6 characters long and include at least one letter and one number.",
        "error"
      );
    }

    // 5️⃣ Check if user already exists by email or phone
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

    // 6️⃣ Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 7️⃣ Create new user
    const user = await User.create({
      name: sanitizedName,
      email: sanitizedEmail,
      phone: sanitizedPhone,
      password: hashedPassword,
      studentId,
      role: "user",       // Default role
      active: true,       // Active by default
      createdAt: new Date(),
    });

    // 8️⃣ Initialize session
    req.session.user = {
      id: user._id,
      name: user.name,
      role: user.role,
    };
    req.session.lastActivity = Date.now();

    console.log(`🟢 New user registered: ${user.email}`);

    // 9️⃣ Redirect to user dashboard
    return res.redirect("/user");

  } catch (err) {
    console.error("🔴 Signup error:", err);

    // 10️⃣ Handle MongoDB duplicate key errors
    if (err.code === 11000) {
      if (err.keyPattern?.email) {
        return handleSignupError(req, res, "Email already registered. Please login instead.", "info", "/login");
      }
      if (err.keyPattern?.phone) {
        return handleSignupError(req, res, "Phone number already registered. Please login instead.", "info", "/login");
      }
    }

    // 11️⃣ Fallback error
    return handleSignupError(req, res, "An unexpected error occurred during signup. Please try again.", "error");
  }
});

// ====== LOGIN ROUTE (Fixed Redirection) ======
app.post("/login", async (req, res) => {
  try {
    const { email, password, remember } = req.body;
    const sanitizedEmail = email?.toLowerCase().trim();

    if (!sanitizedEmail || !password) {
      return handleLoginError(req, res, "Email and password are required.");
    }

    const user = await User.findOne({ email: sanitizedEmail });
    if (!user) return handleLoginError(req, res, "Invalid email or password.");

    const isMatch = await bcrypt.compare(password, user.password || "");
    if (!isMatch) return handleLoginError(req, res, "Invalid email or password.");

    const role = (user.role || "").toLowerCase();

    if (role !== "admin" && !user.active) {
      return handleLoginError(req, res, "Your account is inactive or suspended. Contact support.");
    }

    if (user.phone === undefined || user.phone === null) user.phone = undefined;

    req.session.regenerate(async (err) => {
      if (err) return handleLoginError(req, res, "Login session failed. Try again.");

      req.session.user = {
        id: user._id.toString(),
        name: user.name,
        role,
      };
      req.session.lastActivity = Date.now();

      // Handle Remember Me
      try {
        await handleRememberMe(user, res, remember);
      } catch (rememberErr) {
        console.warn("⚠️ Remember Me failed:", rememberErr.message);
      }

      req.session.save((saveErr) => {
        if (saveErr) return handleLoginError(req, res, "Session save failed. Try again.");

        console.log("✅ User logged in:", user.email, "| Role:", role);

        // Redirect based on role
        if (role === "admin") return res.redirect("/admin");
        return res.redirect("/user");
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

    // 1️⃣ Validate all fields
    if (!email || !newPassword || !confirmPassword) {
      return handleFlashRedirect(res, "/reset-password", "All fields are required.", "error");
    }

    // 2️⃣ Check if passwords match
    if (newPassword !== confirmPassword) {
      return handleFlashRedirect(res, "/reset-password", "Passwords do not match.", "error");
    }

    // 3️⃣ Enforce strong password (min 6 chars, at least 1 letter & 1 number)
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
    if (!passwordRegex.test(newPassword)) {
      return handleFlashRedirect(
        res,
        "/reset-password",
        "Password must be at least 6 characters long and include at least one letter and one number.",
        "error"
      );
    }

    // 4️⃣ Find user by email
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return handleFlashRedirect(res, "/reset-password", "No account found with that email address.", "error");
    }

    // 5️⃣ Update password with hashed version
    user.password = await bcrypt.hash(newPassword, 10);

    // Optional: clear any Remember Me token for security
    user.rememberToken = null;

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

    // 1️⃣ Must provide either email or phone
    if (!email && !phone) {
      return res.status(400).json({
        success: false,
        exists: false,
        message: "Please provide an email or phone number.",
      });
    }

    // 2️⃣ Build query dynamically
    const query = [];
    if (typeof email === "string" && email.trim()) query.push({ email: email.toLowerCase().trim() });
    if (typeof phone === "string" && phone.trim()) query.push({ phone: phone.trim() });

    if (!query.length) {
      return res.status(400).json({
        success: false,
        exists: false,
        message: "Invalid email or phone format.",
      });
    }

    // 3️⃣ Check if user exists
    const user = await User.findOne({ $or: query });

    return res.json({
      success: true,
      exists: !!user,
      message: user ? "A user with this email or phone already exists." : "No matching user found.",
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

// ================== PRODUCT ROUTES ==================

// ========== ADMIN PRODUCTS JSON (for Admin Dashboard) ==========
app.get("/admin/products/json", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const products = await Product.find();

    // Ensure every product includes mainImage and consistent structure
    const formattedProducts = products.map(p => {
      const obj = p.toObject();

      // Handle backward compatibility — if old product used only mainImage
      if ((!obj.images || obj.images.length === 0) && obj.mainImage) {
        obj.images = [obj.mainImage];
      }

      // Always define mainImage as the first image
      obj.mainImage = obj.images?.[0] || null;

      return obj;
    });

    res.json(formattedProducts);
  } catch (err) {
    console.error("Error loading admin products:", err);
    res.status(500).json({ success: false, message: "Failed to load products" });
  }
});

// ========== PUBLIC PRODUCTS JSON (for Shop Page) ==========
app.get("/products/json", async (req, res) => {
  try {
    const products = await Product.find();

    // Format data for frontend: always provide mainImage and fallback handling
    const productsWithPath = products.map(p => ({
      ...p.toObject(),

      // If no images array, fallback to old single mainImage
      images: (p.images && p.images.length > 0)
        ? p.images
        : (p.mainImage ? [p.mainImage] : []),

      // Ensure mainImage always exists (for UI)
      mainImage: p.mainImage || (p.images?.[0] || null)
    }));

    res.json(productsWithPath);
  } catch (err) {
    console.error("Failed to fetch products:", err);
    res.status(500).json({ success: false, message: "Failed to fetch products" });
  }
});

// ========== ADD PRODUCT (Supports Up to 4 Images + Dropdown Fields) ==========
app.post(
  "/admin/products",
  upload.array("images", 4), // Accept up to 4 images
  ensureAuthenticated,
  requireAdmin,
  async (req, res) => {
    try {
      const { title, marketPrice, salePrice, description, onSale, category, condition, brand } = req.body;
      let imageUrls = [];

      // Validation — at least one image required
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ success: false, message: "At least one image is required." });
      }

      // Upload each image to Cloudinary
      for (const file of req.files) {
        const result = await cloudinary.uploader.upload(file.path, { folder: "products" });
        imageUrls.push(result.secure_url);
      }

      // First image = main display image
      const mainImage = imageUrls[0];

      // Create new product document
      const newProduct = await Product.create({
        title,
        marketPrice,
        salePrice,
        description,
        category: category || "Unspecified",     // Dropdown default fallback
        condition: condition || "Unspecified",
        brand: brand || "Unspecified",
        onSale: onSale === "on" || onSale === "true",
        images: imageUrls,
        mainImage
      });

      // Emit new product event (for real-time admin/shop updates)
      io.emit("newProduct", newProduct);

      res.json({ success: true, product: newProduct });
    } catch (err) {
      console.error("Error adding product:", err);
      res.status(500).json({ success: false, message: err.message });
    }
  }
);

// ========== EDIT PRODUCT (Supports Image Replacement + Dropdown Updates) ==========
app.post(
  "/admin/products/edit/:id",
  upload.array("images", 4), // Up to 4 replacement images
  ensureAuthenticated,
  requireAdmin,
  async (req, res) => {
    try {
      const { title, marketPrice, salePrice, description, onSale, category, condition, brand } = req.body;

      // Find the product by ID
      const product = await Product.findById(req.params.id);
      if (!product)
        return res.status(404).json({ success: false, message: "Product not found" });

      // If new images uploaded, replace old ones
      if (req.files && req.files.length > 0) {
        const uploadedImages = [];
        for (const file of req.files) {
          const result = await cloudinary.uploader.upload(file.path, { folder: "products" });
          uploadedImages.push(result.secure_url);
        }
        product.images = uploadedImages;
        product.mainImage = uploadedImages[0]; // Always first image as main
      }

      // Merge updated fields — retain old values if not provided
      Object.assign(product, {
        title,
        marketPrice,
        salePrice,
        description,
        category: category || product.category || "Unspecified",
        condition: condition || product.condition || "Unspecified",
        brand: brand || product.brand || "Unspecified",
        onSale: onSale === "on" || onSale === "true"
      });

      await product.save();

      // Emit real-time update event
      io.emit("updateProduct", product);

      res.json({ success: true, product });
    } catch (err) {
      console.error("Error editing product:", err);
      res.status(500).json({ success: false, message: err.message });
    }
  }
);

// ========== DELETE PRODUCT ==========
app.post("/admin/products/delete/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);

    // Handle not found error
    if (!product)
      return res.status(404).json({ success: false, message: "Product not found" });

    // Emit delete event for real-time UI sync
    io.emit("deleteProduct", product._id);

    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting product:", err);
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

// Get user loans page
app.get("/loans", ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user?.id; // FIXED: Changed _id to id
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
    const userId = req.session.user?.id; // FIXED: Changed _id to id
    if (!userId) return res.status(401).json({ success: false, message: "Not logged in" });

    const { description, itemValue, loanAmount, loanPeriod } = req.body;

    // Validate required fields
    if (!description || !itemValue || !loanAmount || !loanPeriod) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    let imageUrl = null;
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, { folder: "loans" });
      imageUrl = result.secure_url;
    }

    const loan = await Loan.create({
      user: userId,
      itemImage: imageUrl,
      description,
      itemValue,
      loanAmount,
      loanPeriod,
      status: "Pending",
    });

    // Emit event to all clients; frontend can filter by user
    io.emit("loanCreated", loan);

    res.json({ success: true, loan });
  } catch (err) {
    console.error("Loan submission error:", err);
    res.status(500).json({ success: false, message: "Failed to submit loan" });
  }
});

// Get user loans JSON
app.get("/loans/list", ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user?.id; // FIXED: Changed _id to id
    if (!userId) return res.status(401).json([]);

    const loans = await Loan.find({ user: userId }).sort({ createdAt: -1 });
    res.json(loans);
  } catch (err) {
    console.error("Error fetching user loans:", err);
    res.status(500).json([]);
  }
});

// Admin view loans page
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
    const validStatuses = ["Pending", "Approved", "Rejected", "Visit shop"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, message: "Invalid status" });
    }

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

// Delete a loan (admin only)
app.delete("/admin/loans/:id", ensureAuthenticated, requireAdmin, async (req, res) => {
  try {
    const loan = await Loan.findByIdAndDelete(req.params.id);

    if (!loan) {
      return res.status(404).json({ success: false, message: "Loan not found" });
    }

    // Emit real-time deletion to all connected clients
    io.emit("loanDeleted", req.params.id);

    res.json({ success: true, message: "Loan deleted successfully" });
  } catch (err) {
    console.error("Loan deletion error:", err);
    res.status(500).json({ success: false, message: "Failed to delete loan" });
  }
});

// ================== GAMING BOOKINGS ==================

app.post("/gaming/book", ensureAuthenticated, async (req, res) => {
  try {
    const { game, console, date, timeSlot } = req.body;

    if (!game || !console || !date || !timeSlot) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields (game, console, date, timeSlot).",
      });
    }

    // Prevent duplicate bookings for the same user and time slot
    const existingBooking = await Booking.findOne({
      user: req.session.user.id,
      date,
      timeSlot,
    });

    if (existingBooking) {
      return res.status(400).json({
        success: false,
        message: "You already have a booking for this time slot.",
      });
    }

    // Create new booking
    const booking = await Booking.create({
      user: req.session.user.id,
      game,
      console,
      date: new Date(date),
      timeSlot,
    });

    const populatedBooking = await Booking.findById(booking._id).populate(
      "user",
      "name email"
    );

    // Real-time update for admins
    io.emit("booking:new", { ...populatedBooking.toObject(), isNew: true });

    res.json({
      success: true,
      message: "Booking created successfully.",
      data: populatedBooking,
    });
  } catch (err) {
    console.error("Error creating booking:", err);
    res.status(500).json({
      success: false,
      message: "Failed to create booking.",
      error: err.message,
    });
  }
});

// ================== ADMIN BOOKING UPDATE ==================

app.post(
  "/admin/bookings/update/:id",
  ensureAuthenticated,
  requireAdmin,
  async (req, res) => {
    try {
      const { status } = req.body;
      if (!status) {
        return res
          .status(400)
          .json({ success: false, message: "Status is required." });
      }

      const booking = await Booking.findById(req.params.id);
      if (!booking) {
        return res
          .status(404)
          .json({ success: false, message: "Booking not found." });
      }

      booking.status = status;
      await booking.save();

      const populatedBooking = await Booking.findById(booking._id).populate(
        "user",
        "name email"
      );

      io.emit("booking:updated", populatedBooking);

      res.json({
        success: true,
        message: "Booking status updated successfully.",
        data: populatedBooking,
      });
    } catch (err) {
      console.error("Error updating booking:", err);
      res.status(500).json({
        success: false,
        message: "Failed to update booking.",
        error: err.message,
      });
    }
  }
);

// ================== ADMIN GET ALL BOOKINGS ==================

app.get(
  "/admin/bookings/json",
  ensureAuthenticated,
  requireAdmin,
  async (req, res) => {
    try {
      const bookings = await Booking.find()
        .populate("user", "name email")
        .sort({ createdAt: -1 });

      const now = new Date();

      const bookingsWithFlag = bookings.map((b) => {
        const bookingObj = b.toObject();
        bookingObj.user ||= { name: "Unknown User", email: "N/A" };
        const createdAt = b.createdAt instanceof Date ? b.createdAt : null;
        bookingObj.isNew = createdAt ? (now - createdAt) / 1000 < 10 : false;
        bookingObj.createdAt = createdAt;
        return bookingObj;
      });

      res.json({
        success: true,
        message: "Admin bookings fetched successfully.",
        data: bookingsWithFlag,
      });
    } catch (err) {
      console.error("Error fetching admin bookings:", err);
      res.status(500).json({
        success: false,
        message: "Failed to fetch admin bookings.",
        error: err.message,
      });
    }
  }
);

// ================== USER GET BOOKINGS ==================

app.get("/gaming/bookings/json", ensureAuthenticated, async (req, res) => {
  try {
    const bookings = await Booking.find({ user: req.session.user.id })
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    const safeBookings = bookings.map((b) => {
      const bookingObj = b.toObject();
      bookingObj.user ||= { name: "Unknown User", email: "N/A" };
      return bookingObj;
    });

    res.json({
      success: true,
      message: "User bookings fetched successfully.",
      data: safeBookings,
    });
  } catch (err) {
    console.error("Error fetching user bookings:", err);
    res.status(500).json({
      success: false,
      message: "Failed to fetch user bookings.",
      error: err.message,
    });
  }
});

// ================== ADMIN DELETE BOOKING ==================

app.delete(
  "/admin/bookings/:id/delete",
  ensureAuthenticated,
  requireAdmin,
  async (req, res) => {
    try {
      const booking = await Booking.findByIdAndDelete(req.params.id);
      if (!booking)
        return res
          .status(404)
          .json({ success: false, message: "Booking not found." });

      io.emit("booking:deleted", { id: req.params.id });

      res.json({
        success: true,
        message: "Booking deleted successfully.",
      });
    } catch (err) {
      console.error("Error deleting booking:", err);
      res.status(500).json({
        success: false,
        message: "Failed to delete booking.",
        error: err.message,
      });
    }
  }
);

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
    const user = await User.findById(req.session.user.id);
    if (!user) {
      req.session.flash = { type: "error", message: "User not found." };
      return res.redirect("/login");
    }

    // Update basic fields
    user.name = name || user.name;
    user.phone = phone || user.phone;
    user.studentId = studentId || user.studentId;

    // Update profile image if new file uploaded - FIXED: removed non-existent method
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, { 
        folder: "profile-images" 
      });
      user.image = result.secure_url;
      user.imageId = result.public_id;
    }

    await user.save();

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
    const user = await User.findById(req.session.user.id);
    if (!user) {
      req.session.flash = { type: "error", message: "User not found." };
      return res.redirect("/login");
    }

    // Delete image using the schema method
    if (user.imageId) {
      try {
        await cloudinary.uploader.destroy(user.imageId);
      } catch (err) {
        console.warn("Failed to remove image from Cloudinary:", err.message);
      }
    }

    user.image = "https://via.placeholder.com/150"; // FIXED: Changed to reliable URL
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

// ===================== PUBLIC PAGES =====================
app.get("/about", (req, res) => res.render("about"));
app.get("/contact", (req, res) => res.render("contact"));
app.get("/whatscoming", (req, res) => res.render("whatscoming"));
app.get("/shop", (req, res) => res.render("shop"));
app.get("/terms", (req, res) => res.render("terms"));
app.get("/signup", (req, res) => res.render("signup"));
app.get("/login", (req, res) => res.render("login"));
app.get("/reset-password", (req, res) => res.render("reset-password"));
app.get("/privacy-policy", (req, res) => res.render("privacy-policy"));
app.get("/refund-policy", (req, res) => res.render("refund-policy"));
app.get("/booking", (req, res) => res.render("booking"));
app.get("/blog", (req, res) => res.render("blog"));
app.get("/home", (req, res) => res.redirect("/")); // ADDED: Home route for logout redirect
app.get("/gaming", (req, res) => res.render("gaming"));

// ===================== USER / ADMIN PAGES =====================
app.get("/user", ensureAuthenticated, (req, res) => res.render("user"));
// REMOVED: Duplicate admin route that was causing conflicts
app.get("/edit-user", ensureAuthenticated, (req, res) => res.render("edit-user"));
// REMOVED: Duplicate loans route that was causing conflicts
app.get("/message", ensureAuthenticated, (req, res) => res.render("message"));

// ==================== LOGOUT ROUTE (Universal & Safe) ====================
app.get("/logout", async (req, res) => {
  try {
    const role = req.session?.user?.role || "user";

    // 1️⃣ Try to clear Remember Me token if user exists
    if (req.user) {
      try {
        await handleRememberMe(req.user, res, false);
      } catch (rememberErr) {
        console.warn("⚠️ Remember Me clear failed:", rememberErr.message);
      }
    }

    // 2️⃣ Handle missing session gracefully
    if (!req.session) {
      console.warn("⚠️ No session found during logout");
      clearAllCookies(res);
      return res.redirect("/home");
    }

    // 3️⃣ Destroy the session safely and clear cookies
    req.session.destroy(async (err) => {
      if (err) {
        console.warn("⚠️ Session destroy failed:", err.message);
      }

      clearAllCookies(res);

      console.log(`✅ ${role.toUpperCase()} logged out successfully`);
      return res.redirect("/home");
    });
  } catch (err) {
    console.error("❌ Logout error:", err);
    clearAllCookies(res);
    return res.redirect("/home");
  }
});

// ==================== COOKIE CLEAR HELPER ====================
function clearAllCookies(res) {
  try {
    // Clear both main session and Remember Me
    res.clearCookie("connect.sid", {
      path: "/",
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
    res.clearCookie("rememberMeToken", { path: "/" });
  } catch (err) {
    console.warn("⚠️ Failed to clear cookies:", err.message);
  }
}


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