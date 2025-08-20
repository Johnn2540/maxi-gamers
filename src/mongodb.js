const mongoose = require("mongoose");

mongoose.connect("mongodb://localhost:27017/loginSignup", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log("MongoDB connected");
})
.catch((err) => {
    console.error("MongoDB connection failed:", err.message);
});

// Define schema
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,   // prevent duplicate emails
        lowercase: true,
        trim: true,
        match: [/^\S+@\S+\.\S+$/, "Please use a valid email address"]
    },
    phone: {
        type: String,
        required: true,
        unique: true,   // no duplicate phone numbers
        match: [/^\d{10,15}$/, "Please enter a valid phone number"] // 10–15 digits
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ["user", "admin"], 
        default: "user"
    }
});

// Create model
const Collection = mongoose.model("Collection1", userSchema);

module.exports = Collection;





