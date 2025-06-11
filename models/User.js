const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '/images/default-avatar.png' },
  status: { type: String, enum: ['online', 'offline', 'busy', 'away'], default: 'offline' },
  lastSeen: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
module.exports = User;