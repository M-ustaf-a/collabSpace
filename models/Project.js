const mongoose = require("mongoose");

const projectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'completed', 'paused'], default: 'active' }
});

const Project = mongoose.model("Project", projectSchema);
module.exports = Project;