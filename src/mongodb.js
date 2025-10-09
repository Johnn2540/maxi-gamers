const mongoose = require("mongoose");
require("dotenv").config();

const MONGO_URI = process.env.MONGO_URI;

// ------------------ CONNECT FUNCTION ------------------
const connectDB = async () => {
  if (!MONGO_URI) {
    console.error("❌ MONGO_URI is not defined in .env");
    process.exit(1);
  }

  try {
    await mongoose.connect(MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("✅ Connected to MongoDB Atlas");
  } catch (err) {
    console.error("❌ MongoDB Atlas connection error:", err);
    process.exit(1);
  }
};

// ------------------ SCHEMAS ------------------

// User schema
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String, unique: true, sparse: true, trim: true }, // sparse allows multiple nulls
    password: { type: String, required: false },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    active: { type: Boolean, default: true },
    verificationToken: { type: String, default: null },
    lastVerificationSent: { type: Date, default: null },
    studentId: { type: String, default: null },
    image: { type: String, default: "/images/default-profile.png" }, // default placeholder
    imageId: { type: String, default: null }, // Cloudinary public_id
    googleId: { type: String, unique: true, sparse: true }, // sparse prevents duplicate null error
    rememberToken: { type: String, default: null },
  },
  { timestamps: true }
);

// Trim and clean fields before saving
userSchema.pre("save", function (next) {
  // Trim and clean basic fields
  if (this.name) this.name = this.name.trim();
  if (this.email) this.email = this.email.toLowerCase().trim();

  // Handle phone (avoid saving null)
  this.phone = this.phone ? this.phone.trim() : undefined;

  // Only store googleId if it exists
  this.googleId = this.googleId || undefined;

  // Ensure default image if none exists
  if (!this.image) this.image = "/images/default-profile.png";
  if (!this.imageId) this.imageId = null;

  next();
});

// Product schema
const productSchema = new mongoose.Schema({
  title: { type: String, required: true },
  marketPrice: { type: Number, required: true },
  salePrice: { type: Number, required: true },
  description: { type: String },
  onSale: { type: Boolean, default: false },
  image: { type: String },
});

// Leaderboard schema
const leaderboardSchema = new mongoose.Schema({
  player: { type: String, required: true },
  score: { type: Number, required: true },
});

// Booking schema
const bookingSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    game: { type: String, required: true },
    console: { type: String, required: true },
    date: { type: Date, required: true },
    timeSlot: { type: String, required: true },
    status: { type: String, enum: ["Pending", "Confirmed", "Completed", "Cancelled"], default: "Pending" },
  },
  { timestamps: true }
);

// TopBarMessage schema
const topBarMessageSchema = new mongoose.Schema({
  content: { type: String, required: true },
  active: { type: Boolean, default: true },
  order: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

// Loan schema
const loanSchema = new mongoose.Schema(
  {
    images: [{ type: String }], // Array of image URLs (Cloudinary)
    description: { type: String, required: true, trim: true },
    itemValue: { type: Number, required: true },
    loanAmount: { type: Number, required: true },
    loanPeriod: { type: Number, required: true }, // e.g., in months or days
    status: { 
      type: String, 
      enum: ["Pending", "Approved", "Rejected", "Completed"], 
      default: "Pending" 
    },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: true } // adds createdAt and updatedAt automatically
);


// Message schema
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  content: { type: String, required: [true, "Message content is required"] },
  reply: { type: String, default: null },
  status: { type: String, enum: ["Pending", "Replied"], default: "Pending" },
  createdAt: { type: Date, default: Date.now },
});

// ------------------ MODEL REGISTRATION ------------------
const User = mongoose.models.User || mongoose.model("User", userSchema);
const Product = mongoose.models.Product || mongoose.model("Product", productSchema);
const Leaderboard = mongoose.models.Leaderboard || mongoose.model("Leaderboard", leaderboardSchema);
const Booking = mongoose.models.Booking || mongoose.model("Booking", bookingSchema);
const TopBarMessage = mongoose.models.TopBarMessage || mongoose.model("TopBarMessage", topBarMessageSchema);
const Loan = mongoose.models.Loan || mongoose.model("Loan", loanSchema);
const Message = mongoose.models.Message || mongoose.model("Message", messageSchema);

// ------------------ EXPORTS ------------------
module.exports = {
  connectDB, // now properly defined
  User,
  Product,
  Leaderboard,
  Booking,
  TopBarMessage,
  Loan,
  Message,
  mongoose,
};



