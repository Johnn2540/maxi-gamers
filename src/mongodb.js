const mongoose = require("mongoose");
require("dotenv").config(); // Load environment variables from .env

// ------------------ CONNECT TO MONGODB ------------------
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb://127.0.0.1:27017/LoginSignup"; // fallback to local DB

mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ------------------ SCHEMAS ------------------

// USER SCHEMA
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    active: { type: Boolean, default: true },
    studentId: { type: String },
    image: { type: String, default: null }, // Profile image URL/path
  },
  { timestamps: true }
);

// PRODUCT SCHEMA
const productSchema = new mongoose.Schema({
  title: { type: String, required: true },
  marketPrice: { type: Number, required: true },
  salePrice: { type: Number, required: true },
  description: { type: String },
  onSale: { type: Boolean, default: false },
  image: { type: String },
});

// LEADERBOARD SCHEMA
const leaderboardSchema = new mongoose.Schema({
  player: { type: String, required: true },
  score: { type: Number, required: true },
});

// BOOKING SCHEMA
const bookingSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  game: { type: String, required: true },
  console: { type: String, required: true },
  date: { type: Date, required: true },
  timeSlot: { type: String, required: true },
  status: {
    type: String,
    enum: ["Pending", "Confirmed", "Completed", "Cancelled"],
    default: "Pending",
  },
  createdAt: { type: Date, default: Date.now },
});

// TOP BAR MESSAGE SCHEMA
const topBarMessageSchema = new mongoose.Schema({
  content: { type: String, required: true },
  active: { type: Boolean, default: true },
  order: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

// LOAN SCHEMA
const loanSchema = new mongoose.Schema({
  itemImage: String,
  description: String,
  itemValue: Number,
  loanAmount: Number,
  loanPeriod: Number,
  status: { type: String, default: "Pending" },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
});

// MESSAGE SCHEMA
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  content: { type: String, required: [true, "Message content is required"] },
  reply: { type: String, default: null },
  status: { type: String, enum: ["Pending", "Replied"], default: "Pending" },
  createdAt: { type: Date, default: Date.now },
});

// ------------------ MODELS ------------------
const User = mongoose.models.User || mongoose.model("User", userSchema);
const Product =
  mongoose.models.Product || mongoose.model("Product", productSchema);
const Leaderboard =
  mongoose.models.Leaderboard ||
  mongoose.model("Leaderboard", leaderboardSchema);
const Booking =
  mongoose.models.Booking || mongoose.model("Booking", bookingSchema);
const TopBarMessage =
  mongoose.models.TopBarMessage ||
  mongoose.model("TopBarMessage", topBarMessageSchema);
const Loan = mongoose.models.Loan || mongoose.model("Loan", loanSchema);
const Message =
  mongoose.models.Message || mongoose.model("Message", messageSchema);

// ------------------ EXPORT ------------------
module.exports = {
  User,
  Product,
  Leaderboard,
  Booking,
  TopBarMessage,
  Loan,
  Message,
};


