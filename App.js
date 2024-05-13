// app.js

const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LocalStrategy = require('passport-local').Strategy;

const app = express();
const PORT = 3000;

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/enhanced_auth_db', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error(err));

// User Model
const User = mongoose.model('User', {
  username: String,
  password: String,
  email: String,
  name: String,
  bio: String,
  phone: String,
  role: {
    type: String,
    default: 'user' // 'user' or 'admin'
  },
  profileVisibility: {
    type: String,
    default: 'public' // 'public' or 'private'
  }
});

// Middleware
app.use(express.json());
app.use(passport.initialize());

// Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, 'secret', (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Authorization Middleware for Admin
const isAdmin = (req, res, next) => {
  if (req.user.role === 'admin') {
    next();
  } else {
    res.sendStatus(403);
  }
};

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: 'YOUR_GOOGLE_CLIENT_ID',
  clientSecret: 'YOUR_GOOGLE_CLIENT_SECRET',
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ email: profile.emails[0].value });
    if (!user) {
      // If user does not exist, create a new one
      user = new User({
        email: profile.emails[0].value,
        name: profile.displayName
      });
      await user.save();
    }
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Local Strategy
passport.use(new LocalStrategy(
    {
      usernameField: 'username',
      passwordField: 'password'
    },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });
        if (!user) {
          return done(null, false, { message: 'Incorrect username.' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          return done(null, false, { message: 'Incorrect password.' });
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  ));

// Google OAuth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
  const token = jwt.sign(req.user, 'secret');
  res.json({ token });
});

// Register a new user
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword, email });
  await user.save();
  res.status(201).send('User registered successfully');
});

// User login
app.post('/login', passport.authenticate('local', { session: false }), (req, res) => {
  const token = jwt.sign(req.user, 'secret');
  res.json({ token });
});

// Get user profile
app.get('/profile', authenticateJWT, async (req, res) => {
  const user = await User.findById(req.user._id);
  // Check if profile is public or user is admin before sending profile data
  if (user.profileVisibility === 'public' || req.user.role === 'admin') {
    res.json(user);
  } else {
    res.sendStatus(403); // Forbidden
  }
});

// Set profile visibility (public or private)
app.post('/profile/visibility', authenticateJWT, async (req, res) => {
  const { visibility } = req.body;
  if (visibility === 'public' || visibility === 'private') {
    await User.findByIdAndUpdate(req.user._id, { profileVisibility: visibility });
    res.sendStatus(200);
  } else {
    res.status(400).send('Invalid visibility option');
  }
});

// Get all user profiles (only accessible to admin)
app.get('/profiles', authenticateJWT, isAdmin, async (req, res) => {
  const profiles = await User.find({});
  res.json(profiles);
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
