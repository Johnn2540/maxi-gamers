// mongodb.js
const mongoose = require("mongoose");
require("dotenv").config();

// ------------------ CONNECT TO MONGODB ATLAS ------------------
const connectDB = async () => {
  const MONGO_URI = process.env.MONGO_URI;
  if (!MONGO_URI) {
    console.error("❌ MONGO_URI is not defined in .env");
    process.exit(1);
  }

  try {
    await mongoose.connect(MONGO_URI);
    console.log("✅ Connected to MongoDB Atlas");
  } catch (err) {
    console.error("❌ MongoDB Atlas connection error:", err);
    process.exit(1);
  }
};

// ------------------ SCHEMAS ------------------

// USER SCHEMA
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String, trim: true, default: null, sparse: true, unique: true },
    password: { type: String, required: false },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    active: { type: Boolean, default: true },
    verificationToken: { type: String, default: null },
    lastVerificationSent: { type: Date, default: null },
    studentId: { type: String, default: null },
    image: { type: String, default: "/images/default-profile.png" },
    imageId: { type: String, default: null },
    googleId: { type: String, default: null, unique: true, sparse: true },
    rememberToken: { type: String, default: null },
  },
  { timestamps: true }
);

// Trim and normalize before saving
userSchema.pre("save", function (next) {
  if (this.name) this.name = this.name.trim();
  if (this.email) this.email = this.email.toLowerCase().trim();
  this.phone = this.phone ? this.phone.trim() : null;
  this.googleId = this.googleId || null;
  if (!this.image) this.image = "/images/default-profile.png";
  next();
});

// Method to update profile image and delete old Cloudinary image
userSchema.methods.updateProfileImage = async function (newImagePath, cloudinary) {
  try {
    if (this.imageId) {
      await cloudinary.uploader.destroy(this.imageId);
    }

    const result = await cloudinary.uploader.upload(newImagePath, { folder: "profiles" });
    this.image = result.secure_url;
    this.imageId = result.public_id;
    await this.save();

    return this;
  } catch (err) {
    console.error("Error updating profile image:", err);
    throw err;
  }
};

// PRODUCT SCHEMA
const productSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    marketPrice: { type: Number, required: true },
    salePrice: { type: Number, required: true },
    description: { type: String },
    onSale: { type: Boolean, default: false },
    images: {
      type: [String],
      validate: [
        {
          validator: (arr) => arr.length <= 4,
          message: "You can upload at most 4 images per product.",
        },
      ],
      default: [],
    },
  },
  { timestamps: true }
);

// LEADERBOARD SCHEMA
const leaderboardSchema = new mongoose.Schema({
  player: { type: String, required: true },
  score: { type: Number, required: true },
});

// BOOKING SCHEMA
const bookingSchema = new mongoose.Schema(
  {
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
  },
  { timestamps: true }
);

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
const Product = mongoose.models.Product || mongoose.model("Product", productSchema);
const Leaderboard = mongoose.models.Leaderboard || mongoose.model("Leaderboard", leaderboardSchema);
const Booking = mongoose.models.Booking || mongoose.model("Booking", bookingSchema);
const TopBarMessage = mongoose.models.TopBarMessage || mongoose.model("TopBarMessage", topBarMessageSchema);
const Loan = mongoose.models.Loan || mongoose.model("Loan", loanSchema);
const Message = mongoose.models.Message || mongoose.model("Message", messageSchema);

// ------------------ EXPORT ------------------
module.exports = {
  connectDB,
  User,
  Product,
  Leaderboard,
  Booking,
  TopBarMessage,
  Loan,
  Message,
};

