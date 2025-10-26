// --- Imports ---
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// --- App Initialization ---
const app = express();
const PORT = process.env.PORT || 3001;
const API_BASE_URL = '/api';

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- Mongoose Schemas & Models ---

// 1. User Schema
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['Donor', 'Receiver', 'Admin'], required: true },
  location: { type: String }
}, { timestamps: true });

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

UserSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', UserSchema);

// 2. Food Listing Schema
const FoodListingSchema = new mongoose.Schema({
  donor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  donorName: { type: String, required: true },
  description: { type: String, required: true },
  quantity: { type: String, required: true },
  location: { type: String, required: true },
  imageUrl: { type: String, default: 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image' },
  mfgTime: { type: Date, required: true },
  expiryTime: { type: Date, required: true },
  maxClaims: { type: Number, required: true, default: 1, min: 1 },
  claims: [
    {
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      name: { type: String }
    }
  ],
}, { timestamps: true });

const FoodListing = mongoose.model('FoodListing', FoodListingSchema);


// --- *** Admin User Seeding Function *** ---
/**
 * @name seedAdminUser
 * @description Checks if the hardcoded admin user exists on server start.
 * If not, it creates the admin user (`admin@gmail.com` / `adminbalu`).
 */
const seedAdminUser = async () => {
  try {
    const adminEmail = "admin@gmail.com";
    const adminExists = await User.findOne({ email: adminEmail });

    if (!adminExists) {
      console.log("Admin user not found. Creating...");
      const adminUser = new User({
        name: "Admin Balu", // Changed name slightly
        email: adminEmail,
        password: "adminbalu", // The pre-save hook will hash this
        role: "Admin"
      });
      await adminUser.save();
      console.log("Admin user created successfully.");
    } else {
      console.log("Admin user already exists.");
    }
  } catch (error) {
    console.error("Error seeding admin user:", error.message);
  }
};

// --- Database Connection ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected successfully.");
    // --- Call the admin seeder after connection ---
    seedAdminUser();
  })
  .catch(err => console.error("MongoDB connection error:", err));


// --- Authentication Middleware (protect) ---
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select('-password');
      if (!req.user) {
        return res.status(401).json({ message: 'No user found with this token' });
      }
      next();
    } catch (error) {
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }
  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

// --- Admin Middleware (RESTORED) ---
const admin = (req, res, next) => {
  if (req.user && req.user.role === 'Admin') {
    next();
  } else {
    res.status(403).json({ message: 'Not authorized as an admin' });
  }
};

// --- Auth Routes (/api/auth/...) ---
const authRouter = express.Router();

// @route   POST /api/auth/register
authRouter.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: 'Please enter all fields' });
  }
  if (role === 'Admin' || email === 'admin@gmail.com') {
    return res.status(400).json({ message: 'Cannot register with this email or role.' });
  }
  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const user = new User({ name, email, password, role });
    await user.save();
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({
      token,
      user: { _id: user._id, name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   POST /api/auth/login
authRouter.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Please enter all fields' });
  }
  try {
    const user = await User.findOne({ email });
    if (user && (await user.comparePassword(password))) {
      const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
      res.json({
        token,
        user: { _id: user._id, name: user.name, email: user.email, role: user.role },
      });
    } else {
      res.status(400).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.use(`${API_BASE_URL}/auth`, authRouter);

// --- Food Listing Routes (/api/food/...) ---
const foodRouter = express.Router();

// @route   POST /api/food (Create Listing)
foodRouter.post('/', protect, async (req, res) => {
  if (req.user.role !== 'Donor') {
     return res.status(403).json({ message: 'Only donors can create listings.' });
  }
  const { description, quantity, location, imageUrl, mfgTime, expiryTime, maxClaims } = req.body;
  if (!description || !quantity || !location || !mfgTime || !expiryTime || !maxClaims) {
    return res.status(400).json({ message: 'Please fill out all required fields.' });
  }
  if (parseInt(maxClaims, 10) < 1) {
    return res.status(400).json({ message: 'Maximum claims must be at least 1.' });
  }
  try {
    const newListing = new FoodListing({
      donor: req.user._id,
      donorName: req.user.name,
      description, quantity, location,
      imageUrl: imageUrl || undefined,
      mfgTime, expiryTime,
      maxClaims: parseInt(maxClaims, 10),
      claims: []
    });
    const savedListing = await newListing.save();
    res.status(201).json(savedListing);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/food (Get Available Listings for Receivers)
foodRouter.get('/', protect, async (req, res) => {
  try {
    const listings = await FoodListing.find({
      expiryTime: { $gt: new Date() },
      $expr: { $lt: [ { $size: "$claims" }, "$maxClaims" ] }
    }).sort({ expiryTime: 1 });
    res.json(listings);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/food/mylistings (Get Donor's own listings)
foodRouter.get('/mylistings', protect, async (req, res) => {
  if (req.user.role !== 'Donor') {
     return res.status(403).json({ message: 'Only donors can view their listings.' });
  }
  try {
    const listings = await FoodListing.find({ donor: req.user._id }).sort({ createdAt: -1 });
    res.json(listings);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// --- *** NEW: Route for Receivers to see their claims *** ---
// @route   GET /api/food/myclaims
foodRouter.get('/myclaims', protect, async (req, res) => {
  if (req.user.role !== 'Receiver') {
    return res.status(403).json({ message: 'Only receivers can view their claims.' });
  }
  try {
    const listings = await FoodListing.find({
      "claims.userId": req.user._id
    }).sort({ createdAt: -1 });
    res.json(listings);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});


// @route   PUT /api/food/:id/claim (Claim a listing)
foodRouter.put('/:id/claim', protect, async (req, res) => {
  try {
    if (req.user.role !== 'Receiver') {
      return res.status(403).json({ message: 'Only receivers can claim food.' });
    }
    const listing = await FoodListing.findById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'Listing not found' });
    if (new Date(listing.expiryTime) < new Date()) {
      return res.status(400).json({ message: 'This listing has expired.' });
    }
    if (listing.claims.length >= listing.maxClaims) {
      return res.status(400).json({ message: 'This listing has been fully claimed.' });
    }
    const alreadyClaimed = listing.claims.some(
      claim => claim.userId.toString() === req.user._id.toString()
    );
    if (alreadyClaimed) {
      return res.status(400).json({ message: 'You have already claimed this item.' });
    }
    listing.claims.push({
      userId: req.user._id,
      name: req.user.name
    });
    await listing.save();
    res.json({ message: 'Listing claimed successfully!', listing });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   DELETE /api/food/:id (Delete a listing)
// *** UPDATED: Now Admin can also delete ***
foodRouter.delete('/:id', protect, async (req, res) => {
  try {
    const listing = await FoodListing.findById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'Listing not found' });
    
    // Check if user is the donor OR an admin
    if (listing.donor.toString() !== req.user._id.toString() && req.user.role !== 'Admin') {
      return res.status(401).json({ message: 'User not authorized to delete this listing' });
    }
    
    await FoodListing.deleteOne({ _id: req.params.id });
    res.json({ message: 'Listing removed successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.use(`${API_BASE_URL}/food`, foodRouter);

// --- *** Admin Routes (/api/admin/...) (RESTORED) *** ---
const adminRouter = express.Router();

const getDateFilter = (filterQuery) => {
  const dateFilter = {};
  const now = new Date();
  const fieldToFilter = 'createdAt'; 
  if (filterQuery === '1week') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setDate(now.getDate() - 7)) };
  else if (filterQuery === '1month') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setMonth(now.getMonth() - 1)) };
  else if (filterQuery === '3month') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setMonth(now.getMonth() - 3)) };
  else if (filterQuery === '1year') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setFullYear(now.getFullYear() - 1)) };
  return dateFilter;
};

// @route   GET /api/admin/dashboard (Get Dashboard Stats)
adminRouter.get('/dashboard', protect, admin, async (req, res) => {
  try {
    const { filter } = req.query;
    const dateFilter = getDateFilter(filter);

    const userCount = await User.countDocuments();
    const listingCount = await FoodListing.countDocuments(dateFilter);
    
    const availableListings = await FoodListing.find({
      ...dateFilter,
      expiryTime: { $gt: new Date() },
      $expr: { $lt: [ { $size: "$claims" }, "$maxClaims" ] }
    });
    const availableCount = availableListings.length;

    res.json({
      users: { total: userCount },
      listings: { total: listingCount, available: availableCount }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/admin/users (Get All Users)
adminRouter.get('/users', protect, admin, async (req, res) => {
  try {
    const users = await User.find({}).select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/admin/listings (Get All Listings)
adminRouter.get('/listings', protect, admin, async (req, res) => {
  try {
    const { filter } = req.query;
    const dateFilter = getDateFilter(filter);
    const listings = await FoodListing.find(dateFilter).sort({ createdAt: -1 });
    res.json(listings);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.use(`${API_BASE_URL}/admin`, adminRouter);

// --- Server Listen ---
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});