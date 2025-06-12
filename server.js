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
const User = require('./models/User');
const Project = require('./models/Project');
const Task = require('./models/Task');
const Message = require('./models/Message');
const Call = require('./models/Call');
const File = require("./models/File");
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
mongoose.connect(MONGO_URL).then(() => {
  console.log("Connected to the database");
}).catch((err) => {
  console.error("Database connection error:", err);
});

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
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGO_URL,
  }),
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    secure: process.env.NODE_ENV === 'production', // HTTPS in production
    httpOnly: true // Prevent XSS
  }
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
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: function (req, file, cb) {
    // Add file type restrictions if needed
    cb(null, true);
  }
});

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Input validation helpers
const validateUsername = (username) => {
  return username && 
         username.length >= 3 && 
         username.length <= 30 && 
         /^[a-zA-Z0-9_]+$/.test(username);
};

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return email && emailRegex.test(email) && email.length <= 100;
};

const validatePassword = (password) => {
  return password && 
         password.length >= 6 && // Changed from 8 to 6 to match frontend validation
         password.length <= 128;
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
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    const error = req.query.error || null;
    res.render('login', { error });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log('Login attempt:', { username }); // Debug log
    
    // Basic input validation
    if (!username || !password) {
      console.log('Missing username or password');
      return res.render('login', { error: 'Username and password are required' });
    }

    // Trim whitespace
    const trimmedUsername = username.trim();
    const trimmedPassword = password.trim();

    // Find user by username or email (case insensitive)
    const user = await User.findOne({
      $or: [
        { username: { $regex: new RegExp('^' + trimmedUsername + '$', 'i') } },
        { email: { $regex: new RegExp('^' + trimmedUsername + '$', 'i') } }
      ]
    });
    
    console.log('User found:', user ? user.username : 'No user found'); // Debug log
    
    if (user && await bcrypt.compare(trimmedPassword, user.password)) {
      console.log('Password verified successfully');
      req.session.userId = user._id;
      req.session.username = user.username;
      
      // Update user status
      await User.findByIdAndUpdate(user._id, { 
        status: 'online',
        lastLogin: new Date()
      });
      
      console.log('Redirecting to dashboard');
      res.redirect('/dashboard');
    } else {
      console.log('Invalid credentials');
      res.render('login', { error: 'Invalid username or password' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { error: 'An error occurred during login. Please try again.' });
  }
});

app.get('/register', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    const error = req.query.error || null;
    res.render('register', { error });
  }
});

app.post('/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;
    
    console.log('Registration attempt:', { username, email }); // Debug log
    
    // Input validation
    if (!username || !email || !password || !confirmPassword) {
      return res.render('register', { 
        error: 'All fields are required' 
      });
    }

    // Trim inputs
    const trimmedUsername = username.trim();
    const trimmedEmail = email.trim();

    // Validate username
    if (!validateUsername(trimmedUsername)) {
      return res.render('register', { 
        error: 'Username must be 3-30 characters long and contain only letters, numbers, and underscores' 
      });
    }

    // Validate email
    if (!validateEmail(trimmedEmail)) {
      return res.render('register', { 
        error: 'Please enter a valid email address' 
      });
    }

    // Validate password
    if (!validatePassword(password)) {
      return res.render('register', { 
        error: 'Password must be at least 6 characters long' 
      });
    }

    // Check password confirmation
    if (password !== confirmPassword) {
      return res.render('register', { 
        error: 'Passwords do not match' 
      });
    }

    // Check if username already exists (case insensitive)
    const existingUsername = await User.findOne({ 
      username: { $regex: new RegExp('^' + trimmedUsername + '$', 'i') }
    });
    
    if (existingUsername) {
      return res.render('register', { 
        error: 'Username is already taken' 
      });
    }

    // Check if email already exists (case insensitive)
    const existingEmail = await User.findOne({ 
      email: { $regex: new RegExp('^' + trimmedEmail + '$', 'i') }
    });
    
    if (existingEmail) {
      return res.render('register', { 
        error: 'Email is already registered' 
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Create new user
    const user = new User({
      username: trimmedUsername.toLowerCase(),
      email: trimmedEmail.toLowerCase(),
      password: hashedPassword,
      status: 'offline',
      createdAt: new Date()
    });
    
    await user.save();
    console.log('User created successfully:', user.username); // Debug log
    
    // Auto-login after registration
    req.session.userId = user._id;
    req.session.username = user.username;
    
    await User.findByIdAndUpdate(user._id, { 
      status: 'online',
      lastLogin: new Date()
    });
    
    res.redirect('/dashboard');
    
  } catch (error) {
    console.error('Registration error:', error);
    
    // Handle duplicate key errors (in case of race conditions)
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      const message = field === 'username' ? 'Username is already taken' : 'Email is already registered';
      return res.render('register', { error: message });
    }
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      const firstError = Object.values(error.errors)[0];
      return res.render('register', { 
        error: firstError.message || 'Please check your input and try again' 
      });
    }
    
    res.render('register', { 
      error: 'Registration failed. Please try again.' 
    });
  }
});

app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      req.session.destroy();
      return res.redirect('/login');
    }
    
    const projects = await Project.find({
      $or: [
        { owner: req.session.userId },
        { members: req.session.userId }
      ]
    }).populate('owner members');
    
    res.render('dashboard', { user, projects });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.redirect('/login');
  }
});

app.get('/project/:id', requireAuth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id)
      .populate('owner members');
    
    // Check if user has access to this project
    if (!project || (!project.owner.equals(req.session.userId) && 
                     !project.members.some(member => member._id.equals(req.session.userId)))) {
      return res.redirect('/dashboard');
    }
    
    const tasks = await Task.find({ project: req.params.id })
      .populate('assignedTo createdBy');
    const files = await File.find({ project: req.params.id })
      .populate('uploadedBy');
    const user = await User.findById(req.session.userId);
    
    res.render('project', { project, tasks, files, user });
  } catch (error) {
    console.error('Project view error:', error);
    res.redirect('/dashboard');
  }
});

app.post('/project/create', requireAuth, async (req, res) => {
  try {
    const { name, description } = req.body;
    
    // Validate input
    if (!name || name.trim().length === 0) {
      return res.redirect('/dashboard?error=Project name is required');
    }
    
    const project = new Project({
      name: name.trim(),
      description: description ? description.trim() : '',
      owner: req.session.userId,
      members: [req.session.userId]
    });
    
    await project.save();
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Project creation error:', error);
    res.redirect('/dashboard?error=Failed to create project');
  }
});

app.post('/project/:id/invite', requireAuth, async (req, res) => {
  try {
    const { username } = req.body;
    const project = await Project.findById(req.params.id);
    
    // Check if user owns the project
    if (!project || !project.owner.equals(req.session.userId)) {
      return res.redirect(`/project/${req.params.id}?error=Access denied`);
    }
    
    const user = await User.findOne({ username: username.toLowerCase() });
    
    if (user) {
      await Project.findByIdAndUpdate(req.params.id, {
        $addToSet: { members: user._id }
      });
      res.redirect(`/project/${req.params.id}?success=User invited successfully`);
    } else {
      res.redirect(`/project/${req.params.id}?error=User not found`);
    }
  } catch (error) {
    console.error('Invite error:', error);
    res.redirect(`/project/${req.params.id}?error=Failed to invite user`);
  }
});

app.post('/task/create', requireAuth, async (req, res) => {
  try {
    const { title, description, projectId, assignedTo, priority, dueDate } = req.body;
    
    // Validate project access
    const project = await Project.findById(projectId);
    if (!project || (!project.owner.equals(req.session.userId) && 
                     !project.members.includes(req.session.userId))) {
      return res.redirect('/dashboard?error=Access denied');
    }
    
    const task = new Task({
      title: title.trim(),
      description: description ? description.trim() : '',
      project: projectId,
      assignedTo: assignedTo || null,
      createdBy: req.session.userId,
      priority: priority || 'medium',
      dueDate: dueDate || null
    });
    
    await task.save();
    res.redirect(`/project/${projectId}`);
  } catch (error) {
    console.error('Task creation error:', error);
    res.redirect('/dashboard?error=Failed to create task');
  }
});

app.post('/task/:id/update', requireAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const task = await Task.findById(req.params.id);
    
    if (!task) {
      return res.redirect('/dashboard?error=Task not found');
    }
    
    // Validate project access
    const project = await Project.findById(task.project);
    if (!project || (!project.owner.equals(req.session.userId) && 
                     !project.members.includes(req.session.userId))) {
      return res.redirect('/dashboard?error=Access denied');
    }
    
    await Task.findByIdAndUpdate(req.params.id, { status });
    res.redirect(`/project/${task.project}`);
  } catch (error) {
    console.error('Task update error:', error);
    res.redirect('/dashboard?error=Failed to update task');
  }
});

app.post('/upload/:projectId', requireAuth, upload.single('file'), async (req, res) => {
  try {
    const project = await Project.findById(req.params.projectId);
    
    // Validate project access
    if (!project || (!project.owner.equals(req.session.userId) && 
                     !project.members.includes(req.session.userId))) {
      return res.redirect('/dashboard?error=Access denied');
    }
    
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
      
      res.redirect(`/project/${req.params.projectId}?success=File uploaded successfully`);
    } else {
      res.redirect(`/project/${req.params.projectId}?error=No file selected`);
    }
  } catch (error) {
    console.error('File upload error:', error);
    res.redirect(`/project/${req.params.projectId}?error=Failed to upload file`);
  }
});

app.get('/call/:roomId', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.render('call', { roomId: req.params.roomId, user });
  } catch (error) {
    console.error('Call page error:', error);
    res.redirect('/dashboard');
  }
});

app.post('/logout', (req, res) => {
  const userId = req.session.userId;
  
  req.session.destroy(async (err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    
    // Update user status
    try {
      if (userId) {
        await User.findByIdAndUpdate(userId, { 
          status: 'offline',
          lastSeen: new Date()
        });
      }
    } catch (error) {
      console.error('Error updating user status on logout:', error);
    }
    
    res.redirect('/');
  });
});

// Test route for creating a demo user
app.get('/create-demo-user', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash('password', 12);
    
    const demoUser = new User({
      username: 'demo',
      email: 'demo@example.com',
      password: hashedPassword,
      status: 'offline',
      createdAt: new Date()
    });
    
    await demoUser.save();
    res.json({ message: 'Demo user created successfully' });
  } catch (error) {
    if (error.code === 11000) {
      res.json({ message: 'Demo user already exists' });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  if (req.session.userId) {
    res.redirect('/dashboard?error=An unexpected error occurred');
  } else {
    res.redirect('/?error=An unexpected error occurred');
  }
});

// 404 handler
app.use((req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/');
  }
});

// Socket.IO handling
const connectedUsers = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('userConnected', async (userId) => {
    try {
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
    } catch (error) {
      console.error('Error in userConnected:', error);
    }
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
    try {
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
    } catch (error) {
      console.error('Error joining call:', error);
    }
  });

  socket.on('leave-call', async (data) => {
    try {
      const { roomId, userId } = data;
      socket.leave(roomId);
      socket.to(roomId).emit('user-left', { userId, socketId: socket.id });
    } catch (error) {
      console.error('Error leaving call:', error);
    }
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
    try {
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
    } catch (error) {
      console.error('Error in disconnect handler:', error);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;