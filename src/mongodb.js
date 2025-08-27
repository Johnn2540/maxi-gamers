const mongoose = require("mongoose");

// ------------------ CONNECT TO MONGODB ------------------
mongoose
  .connect("mongodb://127.0.0.1:27017/LoginSignup", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// ------------------ USER MODEL ------------------
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  active: { type: Boolean, default: true },
  studentId: { type: String },
});

const User = mongoose.model("User", userSchema);

// ------------------ PRODUCT MODEL ------------------
const productSchema = new mongoose.Schema({
  title: { type: String, required: true },
  marketPrice: { type: Number, required: true },
  salePrice: { type: Number, required: true },
  description: { type: String },
  onSale: { type: Boolean, default: false },
  image: { type: String },
});

const Product = mongoose.model("Product", productSchema);

// ------------------ LEADERBOARD MODEL ------------------
const leaderboardSchema = new mongoose.Schema({
  player: { type: String, required: true },
  score: { type: Number, required: true },
});

const Leaderboard = mongoose.model("Leaderboard", leaderboardSchema);

// ------------------ BOOKING MODEL ------------------
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

const Booking = mongoose.model("Booking", bookingSchema);

// ------------------ EXPORT MODELS ------------------
module.exports = { User, Product, Leaderboard, Booking };





