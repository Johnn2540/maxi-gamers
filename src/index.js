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
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const MongoStore = require('connect-mongo');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = "supersecretkey";

// ================== MIDDLEWARE ==================
app.set("trust proxy", 1); // required on Render/Heroku

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static file serving
app.use(express.static(path.join(__dirname, "../public")));

app.use(
  session({
    name: "connect.sid",
    secret: process.env.SESSION_SECRET || "yourSecretKey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // HTTPS only in prod
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // allow cross-site in prod
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI || 'mongodb+srv://Johnstone2020:Johnstone2020@cluster0.mozeuc4.mongodb.net/maximum_gamers?retryWrites=true&w=majority&appName=Cluster0',
      collectionName: 'sessions'
    }),
  })
);

// Debug middleware
app.use((req, res, next) => {
  console.log("🔎 Session debug:", req.session);
  next();
});

// ================== AUTH MIDDLEWARE ==================
async function ensureAuthenticated(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login"); // Not logged in
  }

  try {
    const user = await User.findById(req.session.user.id);

    if (!user) {
      req.session.destroy(() => res.redirect("/login"));
      return;
    }

    if (user.active === false) {
      req.session.destroy(() =>
        res.status(403).send("Your account is suspended.")
      );
      return;
    }

    req.user = user; // attach full user for later use
    next();
  } catch (err) {
    console.error("Auth check error:", err);
    res.status(500).send("Internal server error");
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).send("Access denied");
  }
  next();
}



// ================== MULTER UPLOAD ==================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "../public/uploads"));
  },
  filename: (req, file, cb) => {
    // Use Date.now() + original file name for uniqueness
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    // Only allow images
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed"));
    }
    cb(null, true);
  },
});


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


app.use(session({
  // ... other settings
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI || 'mongodb+srv://Johnstone2020:Johnstone2020@cluster0.mozeuc4.mongodb.net/maximum_gamers?retryWrites=true&w=majority&appName=Cluster0',
    collectionName: 'sessions'
  }),
}));


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

    const loan = await Loan.create({
      user: req.session.user.id,
      itemImage: req.file ? req.file.filename : null,
      description: req.body.description,
      itemValue: req.body.itemValue,
      loanAmount: req.body.loanAmount,
      loanPeriod: req.body.loanPeriod,
      status: "Pending",
    });

    //  broadcast new loan to admins (match frontend listener)
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
    const loans = await Loan.find().populate("user", "name email").sort({ createdAt: -1 });
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
    const loans = await Loan.find().populate("user", "name email").sort({ createdAt: -1 });
    res.json(loans); // always array
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

    if (!loan) return res.status(404).json({ success: false, message: "Loan not found" });

    // broadcast update (match frontend listener)
    io.emit("loanUpdated", loan);

    res.json({ success: true, loan });
  } catch (err) {
    console.error("Loan update error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});


// ================== USER AUTH ==================

// ================== SIGNUP ==================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password, studentId } = req.body;

    if (await User.findOne({ $or: [{ email }, { phone }] })) {
      return res.status(400).send("User already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      name,
      email,
      phone,
      password: hashedPassword,
      role: "user",
      studentId,
      active: true, // ensure active by default
    });

    req.flash("success_msg", "Signup successful! Please login.");
    res.redirect("/login");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ================== LOGIN ==================
app.post("/login", async (req, res) => {
  try {
    const { name, password } = req.body;
    const user = await User.findOne({ name });

    if (!user) return res.status(400).send("User not found");

    if (!user.active) {
      return res.status(403).send("Your account is suspended. Please contact admin.");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send("Invalid password");
    }

    //  Store session
    req.session.user = { id: user._id, name: user.name, role: user.role };

    //  Redirect based on actual role, not submitted role
    res.redirect(user.role === "admin" ? "/admin" : "/user");
  } catch (err) {
    res.status(500).send(err.message);
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
    if (!user) {
      return res.status(400).send("Invalid username or email");
    }

    if (!user.active) {
      return res.status(403).send("Your account is suspended. Please contact admin.");
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    req.flash("success_msg", "Password updated. Please login.");
    res.redirect("/login");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ================== TOGGLE USER STATUS ==================
app.post("/admin/users/toggle/:id", async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    user.active = !user.active;
    await user.save();

    res.json({ success: true, active: user.active });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
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
      user: req.session.user.id,
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
    const bookingsWithFlag = bookings.map(b => ({
      ...b.toObject(),
      isNew: (now - b.createdAt) / 1000 < 10
    }));

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
      .sort({ createdAt: -1 });

    res.json(bookings); // always array
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

// Update profile details (with optional image upload)
app.post("/profile/update", upload.single("image"), async (req, res) => {
  if (!req.session.user) return res.status(403).send("Login required");

  const { name, phone, studentId } = req.body;

  try {
    const updateData = { name, phone, studentId };

    // If a new image is uploaded, save it
    if (req.file) {
      updateData.image = "/uploads/" + req.file.filename;
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
    user.image = null; // reset to null
    await user.save();
    res.redirect("/profile");
  } catch (err) {
    console.error("Remove image error:", err);
    res.status(500).send("Failed to remove image");
  }
});



// ================== OTHER PAGES ==================
const pages = ["user","signup","login","reset-password","gaming","loans","shop","blog","contact","about","privacy-policy","terms","profile","home","whatscoming","refund-policy","terms"];
pages.forEach(page => app.get("/"+page, (req,res)=>res.render(page)));

// ================== START SERVER ==================
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
});