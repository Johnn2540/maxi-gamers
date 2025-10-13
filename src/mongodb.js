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

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    phone: {
      type: String,
      trim: true,
      default: null,
      sparse: true,
      unique: true,
    },

    password: { type: String, required: false },

    role: { type: String, enum: ["user", "admin"], default: "user" },

    active: { type: Boolean, default: true },

    verificationToken: { type: String, default: null },
    lastVerificationSent: { type: Date, default: null },

    studentId: { type: String, default: null },

    image: {
      type: String,
      default: "/images/default-profile.png",
    },

    imageId: { type: String, default: null },

    googleId: {
      type: String,
      default: null,
      unique: true,
      sparse: true,
    },

    rememberToken: { type: String, default: null },
  },
  { timestamps: true }
);

// 🧹 Trim and normalize before saving
userSchema.pre("save", function (next) {
  if (this.name) this.name = this.name.trim();
  if (this.email) this.email = this.email.toLowerCase().trim();
  this.phone = this.phone ? this.phone.trim() : null;
  this.googleId = this.googleId || null;
  if (!this.image) this.image = "/images/default-profile.png";
  next();
});

// 🖼 Method to update profile image and delete old Cloudinary image
userSchema.methods.updateProfileImage = async function (newImagePath, cloudinary) {
  try {
    // Delete old image if it exists
    if (this.imageId) {
      await cloudinary.uploader.destroy(this.imageId);
    }

    // Upload new image to Cloudinary
    const result = await cloudinary.uploader.upload(newImagePath, { folder: "profiles" });

    // Update user document
    this.image = result.secure_url;
    this.imageId = result.public_id;
    await this.save();

    return this; // return updated user
  } catch (err) {
    console.error("Error updating profile image:", err);
    throw err;
  }
};

// ================== MIDDLEWARE ==================
productSchema.pre("save", function (next) {
  // 🔹 1. Fix: If no images but mainImage exists (old data)
  if ((!this.images || this.images.length === 0) && this.mainImage) {
    this.images = [this.mainImage];
  }

  // 🔹 2. Always ensure mainImage is set correctly
  if (this.images && this.images.length > 0) {
    this.mainImage = this.images[0];
  }

  next();
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



