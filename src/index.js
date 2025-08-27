const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const hbs = require("hbs");
const { User, Product, Leaderboard, Booking } = require("./mongodb");
const session = require("express-session");
const multer = require("multer");
const http = require("http");
const socketIo = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = 3000;
const JWT_SECRET = "supersecretkey";

// ================== SOCKET.IO ==================
io.on("connection", (socket) => {
  console.log("User connected:", socket.id);
});


// ================== MIDDLEWARE ==================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: "yourSecretKey",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);
app.use(express.static(path.join(__dirname, "../public")));

// ================== UPLOAD ==================
const storage = multer.diskStorage({
  destination: (req, file, cb) =>
    cb(null, path.join(__dirname, "../public/uploads")),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});
const upload = multer({ storage });

// ================== VIEW ENGINE ==================
app.set("view engine", "hbs");
app.set("views", path.join(__dirname, "../templates"));

hbs.registerHelper("eq", (a, b) => a === b);
hbs.registerHelper("ne", (a, b) => a !== b);
hbs.registerHelper("and", (a, b) => a && b);
hbs.registerHelper("or", (a, b) => a || b);

// Increment helper for leaderboard rank
hbs.registerHelper("inc", function(value) {
  return parseInt(value) + 1;
});


hbs.registerHelper("chunk", function (array, size) {
  let chunked = [];
  for (let i = 0; i < array.length; i += size) {
    chunked.push(array.slice(i, i + size));
  }
  return chunked;
});


// ================== ROUTES ==================

// Home page
app.get("/", async (req, res) => {
  try {
    const saleProducts = await Product.find({ onSale: true }).limit(6);
    res.render("home", { saleProducts });
  } catch (err) {
    res.status(500).send("Error loading products");
  }
});

// Admin dashboard
app.get("/admin", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Access Denied");
  }
  try {
    const users = await User.find();
    const products = await Product.find();
    const leaderboard = await Leaderboard.find().sort({ score: -1 });
    res.render("admin", { users, products, leaderboard });
  } catch (err) {
    res.status(500).send("Error loading admin panel: " + err.message);
  }
});


// Admin product management page
app.get("/admin/products", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Access Denied");
  }
  const products = await Product.find();
  res.render("admin-products", { products });
});

app.get("/top-leaderboard", async (req, res) => {
  try {
    const topPlayers = await Leaderboard.find().sort({ score: -1 }).limit(10);
    res.json(topPlayers);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch leaderboard" });
  }
});


// ================== ADMIN LEADERBOARD ROUTES ==================

// Add player
app.post("/admin/leaderboard", async (req, res) => {
  try {
    const { player, score } = req.body;
    const newPlayer = new Leaderboard({ player, score });
    await newPlayer.save();
    io.emit("leaderboardUpdate");
    res.redirect("/admin"); // or res.json if using AJAX
  } catch (err) {
    res.status(500).send("Error adding player: " + err.message);
  }
});

// Update player
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

// Delete player
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

// Create new product
app.post("/admin/products", upload.single("image"), async (req, res) => {
  try {
    const { title, marketPrice, salePrice, description, onSale } = req.body;
    const newProduct = new Product({
      title,
      marketPrice,
      salePrice,
      description,
      onSale: onSale === "on" || onSale === "true",
      image: req.file ? "/uploads/" + req.file.filename : null,
    });

    await newProduct.save();
    io.emit("newProduct", newProduct);
    res.json({ success: true, product: newProduct }); // ✅ return JSON instead of redirect
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// Edit existing product
app.post("/admin/products/edit/:id", upload.single("image"), async (req, res) => {
  try {
    const { title, marketPrice, salePrice, description, onSale } = req.body;
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ success: false, message: "Product not found" });
    }

    product.title = title;
    product.marketPrice = marketPrice;
    product.salePrice = salePrice;
    product.description = description;
    product.onSale = onSale === "on" || onSale === "true";

    if (req.file) product.image = "/uploads/" + req.file.filename;

    await product.save();
    io.emit("updateProduct", product);
    res.json({ success: true, product });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Delete product
app.post("/admin/products/delete/:id", async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) {
      return res.status(404).json({ success: false, message: "Product not found" });
    }

    io.emit("deleteProduct", product._id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ================== USER AUTH ==================

app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password, studentId } = req.body;
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser)
      return res.status(400).send("User with this email or phone exists");

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      role: "user",
      studentId: studentId || undefined,
    });
    await newUser.save();
    res.redirect("/user");
  } catch (err) {
    res.status(500).send("Error in signup: " + err.message);
  }
});


// Login
app.post("/login", async (req, res) => {
  try {
    const { name, password, role } = req.body;
    const user = await User.findOne({ name });
    if (!user) return res.status(400).send("User not found");
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send("Invalid password");
    if (role !== user.role) return res.status(403).send("Not authorized");

    req.session.user = { id: user._id, name: user.name, role: user.role };
    res.redirect(user.role === "admin" ? "/admin" : "/user");
  } catch (err) {
    res.status(500).send("Error logging in: " + err.message);
  }
});

// Reset password
app.post("/reset-password", async (req, res) => {
  try {
    const { name, email, newPassword, confirmPassword } = req.body;
    if (newPassword !== confirmPassword)
      return res.status(400).send("Passwords do not match");

    const user = await User.findOne({ name, email });
    if (!user) return res.status(400).send("Invalid username or email");

    // Hash the new password
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.redirect(`/user?token=${token}`);
  } catch (err) {
    res.status(500).send("Error resetting password: " + err.message);
  }
});


// Toggle user status
app.post("/admin/users/toggle/:id", async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== "admin")
      return res.status(403).json({ success: false, message: "Access denied" });

    const user = await User.findById(req.params.id);
    if (!user)
      return res.status(404).json({ success: false, message: "User not found" });

    user.active = !user.active;
    await user.save();
    res.json({ success: true, active: user.active });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================== GAMING BOOKING ROUTES ==================

// User books a gaming session
app.post("/gaming/book", async (req, res) => {
  try {
    if (!req.session.user) 
      return res.status(403).json({ success: false, message: "Login required" });

    const { game, console, date, timeSlot } = req.body;

    const booking = new Booking({
      user: req.session.user.id,
      game,
      console,
      date,
      timeSlot,
    });

    await booking.save();

    // Populate user before emitting
    const populatedBooking = await Booking.findById(booking._id).populate("user", "name email");

    // Emit to admin with a flag for new booking
    io.emit("newBooking", { ...populatedBooking.toObject(), isNew: true });

    res.json({ success: true, message: "Booking created", booking: populatedBooking });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// Admin views all bookings
app.post("/admin/bookings/update/:id", async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== "admin")
      return res.status(403).json({ success: false, message: "Access denied" });

    const { status } = req.body;
    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(404).json({ success: false, message: "Booking not found" });

    booking.status = status;
    await booking.save();

    // Populate user before emitting
    const populatedBooking = await Booking.findById(booking._id).populate("user", "name email");

    io.emit("updateBooking", populatedBooking);

    res.json({ success: true, booking: populatedBooking });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// User fetch their own bookings
app.get("/admin/bookings/json", async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== "admin")
      return res.status(403).json({ success: false, message: "Access denied" });

    const bookings = await Booking.find()
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    // Mark bookings as new if they were created in last 10 seconds (for glow effect)
    const now = new Date();
    const bookingsWithFlag = bookings.map(b => {
      const isNew = (now - b.createdAt) / 1000 < 10; // within last 10 seconds
      return { ...b.toObject(), isNew };
    });

    res.json(bookingsWithFlag);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});




// ================== OTHER PAGES ==================
app.get("/user", (req, res) => res.render("user"));
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

// ================== START SERVER ==================
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

