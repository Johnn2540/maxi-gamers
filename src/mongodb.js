const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

mongoose.connect("mongodb://127.0.0.1:27017/loginSignup", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("MongoDB connected"))
.catch((err) => console.error("MongoDB connection failed:", err.message));

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { 
        type: String, required: true, unique: true, lowercase: true, trim: true,
        match: [/^\S+@\S+\.\S+$/, "Please use a valid email address"]
    },
    phone: { 
        type: String, required: true, unique: true,
        match: [/^\d{10,15}$/, "Please enter a valid phone number"]
    },
    studentId: { type: String, required: false, unique: true, sparse: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["user"], default: "user" },
    active: { type: Boolean, default: true }
}, { timestamps: true });

// Hash password before saving
userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

// Compare password method
userSchema.methods.comparePassword = function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

module.exports = User;







