// server.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const MONGO_URL = process.env.ATLAS;
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// MongoDB Connection
mongoose.connect(MONGO_URL).then(()=>{
  console.log("Connected to the database");
}).catch((err)=>{
  console.error("Database connection error:", err);
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '/images/default-avatar.png' },
  status: { type: String, enum: ['online', 'offline', 'busy', 'away'], default: 'offline' },
  lastSeen: { type: Date, default: Date.now }
});

// Project Schema
const projectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'completed', 'paused'], default: 'active' }
});

// Task Schema
const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['pending', 'in-progress', 'completed'], default: 'pending' },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  dueDate: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

// Message Schema
const messageSchema = new mongoose.Schema({
  content: { type: String, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  room: { type: String, required: true }, // project-id or direct-message-id
  type: { type: String, enum: ['text', 'file', 'image'], default: 'text' },
  fileName: { type: String },
  fileUrl: { type: String },
  timestamp: { type: Date, default: Date.now }
});

// File Schema
const fileSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  uploadedAt: { type: Date, default: Date.now }
});

// Call Schema
const callSchema = new mongoose.Schema({
  roomId: { type: String, required: true, unique: true },
  project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  startTime: { type: Date, default: Date.now },
  endTime: { type: Date },
  status: { type: String, enum: ['active', 'ended'], default: 'active' }
});

const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);
const Task = mongoose.model('Task', taskSchema);
const Message = mongoose.model('Message', messageSchema);
const File = mongoose.model('File', fileSchema);
const Call = mongoose.model('Call', callSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Create uploads directory
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: 'mongodb://localhost:27017/collaboration_system'
  }),
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// View engine
app.set('view engine', 'ejs');
app.set("views", path.join(__dirname, "views"));

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Routes
app.get('/', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    res.render('index');
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.userId = user._id;
      await User.findByIdAndUpdate(user._id, { status: 'online' });
      res.redirect('/dashboard');
    } else {
      res.render('login', { error: 'Invalid credentials' });
    }
  } catch (error) {
    res.render('login', { error: 'Login failed' });
  }
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await user.save();
    req.session.userId = user._id;
    res.redirect('/dashboard');
  } catch (error) {
    res.render('register', { error: 'Registration failed' });
  }
});

app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    const projects = await Project.find({
      $or: [
        { owner: req.session.userId },
        { members: req.session.userId }
      ]
    }).populate('owner members');
    
    res.render('dashboard', { user, projects });
  } catch (error) {
    res.redirect('/login');
  }
});

app.get('/project/:id', requireAuth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id)
      .populate('owner members');
    const tasks = await Task.find({ project: req.params.id })
      .populate('assignedTo createdBy');
    const files = await File.find({ project: req.params.id })
      .populate('uploadedBy');
    const user = await User.findById(req.session.userId);
    
    res.render('project', { project, tasks, files, user });
  } catch (error) {
    res.redirect('/dashboard');
  }
});

app.post('/project/create', requireAuth, async (req, res) => {
  try {
    const { name, description } = req.body;
    const project = new Project({
      name,
      description,
      owner: req.session.userId,
      members: [req.session.userId]
    });
    
    await project.save();
    res.redirect('/dashboard');
  } catch (error) {
    res.redirect('/dashboard');
  }
});

app.post('/project/:id/invite', requireAuth, async (req, res) => {
  try {
    const { username } = req.body;
    const user = await User.findOne({ username });
    
    if (user) {
      await Project.findByIdAndUpdate(req.params.id, {
        $addToSet: { members: user._id }
      });
    }
    
    res.redirect(`/project/${req.params.id}`);
  } catch (error) {
    res.redirect(`/project/${req.params.id}`);
  }
});

app.post('/task/create', requireAuth, async (req, res) => {
  try {
    const { title, description, projectId, assignedTo, priority, dueDate } = req.body;
    const task = new Task({
      title,
      description,
      project: projectId,
      assignedTo: assignedTo || null,
      createdBy: req.session.userId,
      priority,
      dueDate: dueDate || null
    });
    
    await task.save();
    res.redirect(`/project/${projectId}`);
  } catch (error) {
    res.redirect('/dashboard');
  }
});

app.post('/task/:id/update', requireAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const task = await Task.findByIdAndUpdate(req.params.id, { status });
    res.redirect(`/project/${task.project}`);
  } catch (error) {
    res.redirect('/dashboard');
  }
});

app.post('/upload/:projectId', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (req.file) {
      const file = new File({
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        uploadedBy: req.session.userId,
        project: req.params.projectId
      });
      
      await file.save();
      
      // Emit file upload event
      io.to(`project-${req.params.projectId}`).emit('fileUploaded', {
        file: await file.populate('uploadedBy')
      });
    }
    
    res.redirect(`/project/${req.params.projectId}`);
  } catch (error) {
    res.redirect(`/project/${req.params.projectId}`);
  }
});

app.get('/call/:roomId', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.render('call', { roomId: req.params.roomId, user });
  } catch (error) {
    res.redirect('/dashboard');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Socket.IO handling
const connectedUsers = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('userConnected', async (userId) => {
    connectedUsers.set(socket.id, userId);
    await User.findByIdAndUpdate(userId, { status: 'online' });
    
    // Join user to their project rooms
    const projects = await Project.find({
      $or: [{ owner: userId }, { members: userId }]
    });
    
    projects.forEach(project => {
      socket.join(`project-${project._id}`);
    });
    
    // Broadcast user online status
    socket.broadcast.emit('userStatusChanged', { userId, status: 'online' });
  });

  socket.on('joinRoom', (room) => {
    socket.join(room);
  });

  socket.on('sendMessage', async (data) => {
    try {
      const message = new Message({
        content: data.content,
        sender: data.senderId,
        room: data.room,
        type: data.type || 'text'
      });
      
      await message.save();
      const populatedMessage = await Message.findById(message._id).populate('sender');
      
      io.to(data.room).emit('newMessage', populatedMessage);
    } catch (error) {
      console.error('Error sending message:', error);
    }
  });

  // Video call signaling
  socket.on('offer', (data) => {
    socket.to(data.room).emit('offer', data);
  });

  socket.on('answer', (data) => {
    socket.to(data.room).emit('answer', data);
  });

  socket.on('ice-candidate', (data) => {
    socket.to(data.room).emit('ice-candidate', data);
  });

  socket.on('join-call', async (data) => {
    const { roomId, userId } = data;
    socket.join(roomId);
    
    // Update or create call record
    let call = await Call.findOne({ roomId, status: 'active' });
    if (!call) {
      call = new Call({ roomId, participants: [userId] });
    } else {
      call.participants.addToSet(userId);
    }
    await call.save();
    
    socket.to(roomId).emit('user-joined', { userId, socketId: socket.id });
  });

  socket.on('leave-call', async (data) => {
    const { roomId, userId } = data;
    socket.leave(roomId);
    socket.to(roomId).emit('user-left', { userId, socketId: socket.id });
  });

  socket.on('typing', (data) => {
    socket.to(data.room).emit('userTyping', {
      userId: data.userId,
      username: data.username
    });
  });

  socket.on('stopTyping', (data) => {
    socket.to(data.room).emit('userStoppedTyping', {
      userId: data.userId
    });
  });

  socket.on('disconnect', async () => {
    const userId = connectedUsers.get(socket.id);
    if (userId) {
      await User.findByIdAndUpdate(userId, { 
        status: 'offline',
        lastSeen: new Date()
      });
      
      socket.broadcast.emit('userStatusChanged', { userId, status: 'offline' });
      connectedUsers.delete(socket.id);
    }
    
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;