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

const PORT = process.env.PORT || 3000;
const JWT_SECRET = "supersecretkey";

// ================== MIDDLEWARE ==================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "../public")));

app.use(session({
  secret: "yourSecretKey",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === "production", httpOnly: true }
}));

// ================== MULTER UPLOAD ==================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, "../public/uploads")),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});
const upload = multer({ storage });

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

// ================== USERS MANAGEMENT ==================

// Toggle user active/suspended
app.post("/admin/users/toggle/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") 
    return res.status(403).json({ success: false, message: "Access denied" });

  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // Prevent admin from deactivating themselves
    if (user._id.equals(req.session.user.id)) {
      return res.status(400).json({ success: false, message: "Cannot change your own status" });
    }

    user.active = !user.active;
    await user.save();
    res.json({ success: true, active: user.active });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Promote or demote user to admin
app.post("/admin/users/role/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") 
    return res.status(403).json({ success: false, message: "Access denied" });

  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // Prevent admin from changing their own role
    if (user._id.equals(req.session.user.id)) {
      return res.status(400).json({ success: false, message: "Cannot change your own role" });
    }

    user.role = user.role === "admin" ? "user" : "admin";
    await user.save();
    res.json({ success: true, role: user.role });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Delete a user
app.post("/admin/users/delete/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") 
    return res.status(403).json({ success: false, message: "Access denied" });

  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // Prevent admin from deleting themselves
    if (user._id.equals(req.session.user.id)) {
      return res.status(400).json({ success: false, message: "Cannot delete your own account" });
    }

    await user.remove();
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
    res.json(products);
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
    const newProduct = await Product.create({
      title,
      marketPrice,
      salePrice,
      description,
      onSale: onSale === "on" || onSale === "true",
      image: req.file ? "/uploads/" + req.file.filename : null,
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

    Object.assign(product, { title, marketPrice, salePrice, description, onSale: onSale === "on" || onSale === "true" });
    if (req.file) product.image = "/uploads/" + req.file.filename;
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
app.get("/loans", async (req, res) => {
  try {
    const loans = await Loan.find({ user: req.session.user?.id }); // only show current user's applications
    res.render("loans", { loans });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.post("/loans", upload.single("itemImage"), async (req, res) => {
  try {
    if (!req.session.user) {
      if (req.headers.accept.includes("application/json")) {
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

    io.emit("loanUpdate", loan);

    // 👉 If request came from fetch (AJAX), respond JSON
    if (req.headers.accept.includes("application/json")) {
      return res.json({ success: true, loan });
    }

    // 👉 Otherwise, redirect (for normal form POST)
    res.redirect("/loans");
  } catch (err) {
    console.error("Loan submission error:", err);
    if (req.headers.accept.includes("application/json")) {
      return res.status(500).json({ success: false, message: err.message });
    }
    res.status(500).send("Failed to submit loan");
  }
});

app.get("/loans/list", async (req, res) => {
  try {
    const loans = await Loan.find({ user: req.session.user.id });
    res.json(loans);
  } catch (err) {
    res.status(500).json([]);
  }
});

app.post("/admin/loans/:id/status", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") 
    return res.status(403).json({ success: false, message: "Access denied" });

  const { status } = req.body;
  try {
    const loan = await Loan.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!loan) return res.status(404).json({ success: false, message: "Loan not found" });

    io.emit("loanUpdated", loan); // broadcast to all clients
    res.json({ success: true, loan });
  } catch (err) {
    console.error("Loan update error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ================== ADMIN LOANS ==================
app.get("/admin/loans", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") 
    return res.status(403).send("Access Denied");
  try {
    const loans = await Loan.find().populate("user", "name email");
    res.render("admin-loans", { loans });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Reject Loan
app.post("/admin/loans/reject/:id", async (req, res) => {
  await Loan.findByIdAndUpdate(req.params.id, { status: "Rejected" });
  io.emit("loanStatusUpdate", { id: req.params.id, status: "Rejected" });
  res.redirect("/admin/loans");
});

// Request Shop Visit
app.post("/admin/loans/visit/:id", async (req, res) => {
  await Loan.findByIdAndUpdate(req.params.id, { status: "Visit Shop" });
  io.emit("loanStatusUpdate", { id: req.params.id, status: "Visit Shop" });
  res.redirect("/admin/loans");
});

io.on("connection", (socket) => {
  console.log("✅ Admin/User connected:", socket.id);

  // When a user creates a loan
  socket.on("newLoan", async (loanData) => {
    try {
      const newLoan = new Loan(loanData);
      await newLoan.save();

      // Broadcast to ALL (admins + users)
      io.emit("loan:new", newLoan);
    } catch (err) {
      console.error("❌ Loan creation error:", err);
      socket.emit("loanError", "Failed to submit loan.");
    }
  });

  // When an admin updates loan status
  socket.on("updateLoanStatus", async ({ loanId, status }) => {
    try {
      const loan = await Loan.findByIdAndUpdate(
        loanId,
        { status },
        { new: true }
      );

      if (loan) {
        io.emit("loan:update", loan); // broadcast update
      }
    } catch (err) {
      console.error("❌ Loan update error:", err);
      socket.emit("loanError", "Failed to update loan status.");
    }
  });

  socket.on("disconnect", () => {
    console.log("❌ Client disconnected:", socket.id);
  });
});

// ================== MESSAGES ROUTES ==================
// GET all messages (admin view)
app.get("/admin/messages", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).send("Access Denied");
  try {
    const messages = await Message.find()
      .populate("sender", "name email")
      .sort({ createdAt: -1 });
    res.render("admin-messages", { messages });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// GET messages for the current user
app.get("/messages", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  try {
    const messages = await Message.find({ sender: req.session.user.id }).sort({ createdAt: -1 });
    res.render("messages", { messages });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// POST a new message (user sends)
app.post("/messages", async (req, res) => {
  try {
    if (!req.session.user) return res.status(403).json({ success: false, message: "Login required" });
    const { content } = req.body;
    const newMessage = await Message.create({
      sender: req.session.user.id,
      content,
      status: "Pending"
    });

    io.emit("newMessage", newMessage); // broadcast to admins
    if (req.headers.accept.includes("application/json")) {
      return res.json({ success: true, message: newMessage });
    }
    res.redirect("/messages");
  } catch (err) {
    console.error("Message error:", err);
    if (req.headers.accept.includes("application/json")) {
      return res.status(500).json({ success: false, message: err.message });
    }
    res.status(500).send("Failed to send message");
  }
});

// POST reply to a message (admin)
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

    io.emit("messageReplied", message); // broadcast to sender
    res.json({ success: true, message });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE a message (admin)
app.post("/admin/messages/delete/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ success: false, message: "Access denied" });

  try {
    const message = await Message.findByIdAndDelete(req.params.id);
    if (!message) return res.status(404).json({ success: false, message: "Message not found" });

    io.emit("messageDeleted", message._id); // notify front-end
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ================== USER AUTH ==================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password, studentId } = req.body;
    if (await User.findOne({ $or: [{ email }, { phone }] }))
      return res.status(400).send("User already exists");

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, phone, password: hashedPassword, role: "user", studentId });
    res.redirect("/user");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.post("/login", async (req, res) => {
  try {
    const { name, password, role } = req.body;
    const user = await User.findOne({ name });
    if (!user) return res.status(400).send("User not found");
    if (!(await bcrypt.compare(password, user.password))) return res.status(400).send("Invalid password");
    if (role !== user.role) return res.status(403).send("Not authorized");

    req.session.user = { id: user._id, name: user.name, role: user.role };
    res.redirect(role === "admin" ? "/admin" : "/user");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Reset password
app.post("/reset-password", async (req, res) => {
  try {
    const { name, email, newPassword, confirmPassword } = req.body;
    if (newPassword !== confirmPassword) return res.status(400).send("Passwords do not match");

    const user = await User.findOne({ name, email });
    if (!user) return res.status(400).send("Invalid username or email");

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
    res.redirect(`/user?token=${token}`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Toggle user status
app.post("/admin/users/toggle/:id", async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== "admin") return res.status(403).json({ success: false, message: "Access denied" });
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    user.active = !user.active;
    await user.save();
    res.json({ success: true, active: user.active });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ================== GAMING BOOKINGS ==================
app.post("/gaming/book", async (req, res) => {
  try {
    if (!req.session.user) return res.status(403).json({ success: false, message: "Login required" });
    const { game, console, date, timeSlot } = req.body;
    const booking = await Booking.create({ user: req.session.user.id, game, console, date, timeSlot });
    const populatedBooking = await Booking.findById(booking._id).populate("user", "name email");
    io.emit("newBooking", { ...populatedBooking.toObject(), isNew: true });
    res.json({ success: true, booking: populatedBooking });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/admin/bookings/update/:id", async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== "admin") return res.status(403).json({ success: false, message: "Access denied" });
    const { status } = req.body;
    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(404).json({ success: false, message: "Booking not found" });
    booking.status = status;
    await booking.save();
    const populatedBooking = await Booking.findById(booking._id).populate("user", "name email");
    io.emit("updateBooking", populatedBooking);
    res.json({ success: true, booking: populatedBooking });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Fetch bookings JSON
app.get("/admin/bookings/json", async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== "admin") return res.status(403).json({ success: false, message: "Access denied" });
    const bookings = await Booking.find().populate("user", "name email").sort({ createdAt: -1 });
    const now = new Date();
    const bookingsWithFlag = bookings.map(b => ({ ...b.toObject(), isNew: (now - b.createdAt) / 1000 < 10 }));
    res.json(bookingsWithFlag);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


app.get("/gaming/bookings/json", async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(403).json({ success: false, message: "Login required" });
    }
    const bookings = await Booking.find({ user: req.session.user.id }).sort({ createdAt: -1 });
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// ================== MESSAGES & TOP BAR ROUTES ==================

// ======== SOCKET.IO ========
io.on("connection", (socket) => {
  console.log("✅ Client connected:", socket.id);

  socket.on("disconnect", () => {
    console.log("❌ Client disconnected:", socket.id);
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

// --- ADMIN: create/update top bar message ---
app.post("/admin/top-bar", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ success: false, message: "Access denied" });

  const { id, content, order, active } = req.body;

  try {
    let message;
    if (id) {
      message = await TopBarMessage.findByIdAndUpdate(id, { content, order, active }, { new: true });
    } else {
      message = await TopBarMessage.create({ content, order, active });
    }

    io.emit("topBarMessageUpdate", message);
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
    if (!deletedMessage) return res.status(404).json({ success: false, message: "Message not found" });

    io.emit("topBarMessageDeleted", deletedMessage._id);
    res.json({ success: true });
  } catch (err) {
    console.error("Error deleting top bar message:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ================== OTHER PAGES ==================
const pages = ["user","signup","login","reset-password","gaming","loans","shop","blog","contact","about","privacy-policy","terms","profile","home","whatscoming","refund-policy"];
pages.forEach(page => app.get("/"+page, (req,res)=>res.render(page)));

// ================== START SERVER ==================
server.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));