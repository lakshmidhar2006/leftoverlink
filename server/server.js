// --- Imports (ESM Syntax) ---
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';
// ESM specific for __dirname equivalent
import { fileURLToPath } from 'url';

// Load environment variables immediately
dotenv.config();

// ESM equivalent for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- App Initialization ---
const app = express();
const PORT = process.env.PORT || 3001;
const API_BASE_URL = '/api';

// --- File Upload Setup (Multer) ---
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        // Use a placeholder if user is not available during file naming (e.g., during protect middleware)
        const userId = req.user ? req.user._id : 'anon'; 
        cb(null, `${userId}-${Date.now()}${path.extname(file.originalname)}`);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 1024 * 1024 * 5 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error("Error: File upload only supports images (jpg/jpeg/png/gif)"));
    }
});
// --- End Multer Setup ---

// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Serve static files from the 'uploads' directory
app.use('/uploads', express.static(UPLOADS_DIR)); 

// --- Mongoose Schemas & Models ---

// 1. User Schema
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['Donor', 'Receiver', 'Admin'], required: true },
    location: { type: String } // Optional field
}, { timestamps: true });

// Pre-save hook to hash password
UserSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (err) {
        console.error("Error during password hashing:", err);
        next(err);
    }
});

// Method to compare password
UserSchema.methods.comparePassword = function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', UserSchema);

// 2. Food Listing Schema
const FoodListingSchema = new mongoose.Schema({
    donor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    donorName: { type: String, required: true }, // Denormalized for easy display
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
            name: { type: String } // Denormalized for easy display
        }
    ],
}, { timestamps: true });

const FoodListing = mongoose.model('FoodListing', FoodListingSchema);


// --- *** Admin User Seeding Function *** ---
const seedAdminUser = async () => {
    try {
        const adminEmail = "admin@gmail.com";
        const adminExists = await User.findOne({ email: adminEmail });

        if (!adminExists) {
            console.log("Admin user not found. Creating...");
            const adminUser = new User({
                name: "Admin Sreekruthi",
                email: adminEmail,
                password: "adminbalu", // This will be hashed by the pre-save hook
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
        // Seed the admin user after DB connection is successful
        seedAdminUser();
    })
    .catch(err => console.error("MongoDB connection error:", err));


// --- Authentication Middleware (protect) ---
const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            // Get token from header
            token = req.headers.authorization.split(' ')[1];
            
            // Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // Get user from the token
            req.user = await User.findById(decoded.id).select('-password');
            if (!req.user) {
                return res.status(401).json({ message: 'No user found with this token' });
            }
            next();
        } catch (error) {
            console.error("Token verification failed:", error.message); 
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    } else {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};

// --- Admin Middleware ---
const admin = (req, res, next) => {
    if (req.user && req.user.role === 'Admin') {
        next();
    } else {
        res.status(403).json({ message: 'Not authorized as an admin' });
    }
};

// --- Helper: Deletes an image file from the server ---
const deleteFile = (filePath) => {
    // Ensure filePath is a relative path starting with /uploads/
    if (filePath && filePath.startsWith('/uploads/')) {
        const absolutePath = path.join(__dirname, filePath);
        fs.unlink(absolutePath, (err) => {
            if (err) console.error("Failed to delete file:", absolutePath, err);
            else console.log("Successfully deleted file:", absolutePath);
        });
    }
};

// --- Helper: Transform Image URL for Frontend ---
// This prepends the server's base URL to the stored image path
const transformImageUrl = (listing) => {
    const listingObject = listing.toObject ? listing.toObject() : listing;
    if (listingObject.imageUrl && listingObject.imageUrl.startsWith('/uploads/')) {
        listingObject.imageUrl = `http://localhost:${PORT}${listingObject.imageUrl}`;
    }
    return listingObject;
};


// --- Auth Routes (/api/auth/...) ---
const authRouter = express.Router();

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
authRouter.post('/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
        return res.status(400).json({ message: 'Please enter all fields' });
    }
    // Prevent registration as Admin or using admin email
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
        console.error("Registration error:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
});

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user and get token
 * @access  Public
 */
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
        console.error("Login server error:", error.message); 
        res.status(500).json({ message: 'Server error' });
    }
});

app.use(`${API_BASE_URL}/auth`, authRouter);

// --- Food Listing Routes (/api/food/...) ---
const foodRouter = express.Router();

/**
 * @route   POST /api/food
 * @desc    Create a new food listing
 * @access  Private (Donor)
 */
foodRouter.post('/', protect, upload.single('image'), async (req, res) => {
    if (req.user.role !== 'Donor') {
        if (req.file) deleteFile(`/uploads/${req.file.filename}`); 
        return res.status(403).json({ message: 'Only donors can create listings.' });
    }
    const { description, quantity, location, mfgTime, expiryTime, maxClaims } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : undefined;

    if (!description || !quantity || !location || !mfgTime || !expiryTime || !maxClaims) {
        if (req.file) deleteFile(imageUrl);
        return res.status(400).json({ message: 'Please fill out all required fields.' });
    }

    try {
        const newListing = new FoodListing({
            donor: req.user._id,
            donorName: req.user.name,
            description, quantity, location,
            imageUrl: imageUrl || undefined, // Use default if undefined
            mfgTime, expiryTime,
            maxClaims: parseInt(maxClaims, 10),
            claims: []
        });
        const savedListing = await newListing.save();
        
        res.status(201).json(transformImageUrl(savedListing));

    } catch (error) {
        console.error("Error creating listing:", error);
        if (req.file) deleteFile(imageUrl);
        res.status(500).json({ message: 'Server error' });
    }
});

/**
 * @route   PUT /api/food/:id
 * @desc    Update a food listing
 * @access  Private (Donor)
 */
foodRouter.put('/:id', protect, upload.single('image'), async (req, res) => {
    try {
        const listing = await FoodListing.findById(req.params.id);
        if (!listing) return res.status(404).json({ message: 'Listing not found' });

        // Check if the user is the donor
        if (listing.donor.toString() !== req.user._id.toString()) {
            if (req.file) deleteFile(`/uploads/${req.file.filename}`);
            return res.status(401).json({ message: 'User not authorized to update this listing' });
        }

        const { description, quantity, location, mfgTime, expiryTime, maxClaims } = req.body;
        let oldImageUrl = listing.imageUrl;

        if (req.file) {
            const newImageUrl = `/uploads/${req.file.filename}`;
            // Delete old image if it was a custom upload
            if (oldImageUrl && oldImageUrl.startsWith('/uploads/')) {
                deleteFile(oldImageUrl);
            }
            listing.imageUrl = newImageUrl;
        }

        // Update fields
        listing.description = description !== undefined ? description : listing.description;
        listing.quantity = quantity !== undefined ? quantity : listing.quantity;
        listing.location = location !== undefined ? location : listing.location;
        listing.mfgTime = mfgTime !== undefined ? mfgTime : listing.mfgTime;
        listing.expiryTime = expiryTime !== undefined ? expiryTime : listing.expiryTime;
        listing.maxClaims = (maxClaims !== undefined && !isNaN(parseInt(maxClaims, 10))) ? parseInt(maxClaims, 10) : listing.maxClaims;

        const updatedListing = await listing.save();
        
        res.json(transformImageUrl(updatedListing));

    } catch (error) {
        console.error("Error updating listing:", error);
        if (req.file) deleteFile(`/uploads/${req.file.filename}`);
        res.status(500).json({ message: 'Server error' });
    }
});

/**
 * @route   GET /api/food
 * @desc    Get all available listings (for Receivers)
 * @access  Private
 */
foodRouter.get('/', protect, async (req, res) => {
    try {
        const listings = await FoodListing.find({
            expiryTime: { $gt: new Date() }, // Not expired
            $expr: { $lt: [ { $size: "$claims" }, "$maxClaims" ] } // Claims < maxClaims
        }).sort({ expiryTime: 1 }); // Show soonest-to-expire first
        
        res.json(listings.map(transformImageUrl));

    } catch (error) {
        console.error("Error getting all listings:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
});

/**
 * @route   GET /api/food/donor/me
 * @desc    Get all of the logged-in donor's own listings
 * @access  Private (Donor)
 * @UPDATE  Changed from /mylistings to /donor/me to match frontend
 */
foodRouter.get('/donor/me', protect, async (req, res) => {
    if (req.user.role !== 'Donor') {
        return res.status(403).json({ message: 'Only donors can view their listings.' });
    }
    try {
        const listings = await FoodListing.find({ donor: req.user._id }).sort({ createdAt: -1 });
        
        res.json(listings.map(transformImageUrl));

    } catch (error) {
        console.error("Error getting donor listings:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
});

/**
 * @route   GET /api/food/myclaims
 * @desc    Get all listings claimed by the logged-in receiver
 * @access  Private (Receiver)
 */
foodRouter.get('/myclaims', protect, async (req, res) => {
    if (req.user.role !== 'Receiver') {
        return res.status(403).json({ message: 'Only receivers can view their claims.' });
    }
    try {
        const listings = await FoodListing.find({
            "claims.userId": req.user._id
        }).sort({ createdAt: -1 });
        
        res.json(listings.map(transformImageUrl));
        
    } catch (error) {
        console.error("Error getting claims:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
});


/**
 * @route   POST /api/food/:id/claim
 * @desc    Claim a food listing
 * @access  Private (Receiver)
 * @UPDATE  Changed from PUT to POST to match frontend
 */
foodRouter.post('/:id/claim', protect, async (req, res) => {
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
            return res.status(400).json({ message: 'This listing is fully claimed.' });
        }

        const alreadyClaimed = listing.claims.some(claim => claim.userId.toString() === req.user._id.toString());
        if (alreadyClaimed) {
            return res.status(400).json({ message: 'You have already claimed this listing.' });
        }

        // Add claim
        listing.claims.push({
            userId: req.user._id,
            name: req.user.name 
        });

        const updatedListing = await listing.save();
        
        // Return the updated listing (as frontend optimistically updates)
        res.json(transformImageUrl(updatedListing));
    } catch (error) {
        console.error("Error claiming listing:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
});

/**
 * @route   DELETE /api/food/:id
 * @desc    Delete a food listing
 * @access  Private (Donor or Admin)
 */
foodRouter.delete('/:id', protect, async (req, res) => {
    try {
        const listing = await FoodListing.findById(req.params.id);
        if (!listing) return res.status(404).json({ message: 'Listing not found' });

        // Allow if user is the donor OR if user is an Admin
        if (listing.donor.toString() !== req.user._id.toString() && req.user.role !== 'Admin') {
            return res.status(401).json({ message: 'User not authorized to delete this listing' });
        }
        
        // Delete associated image file
        if (listing.imageUrl && listing.imageUrl.startsWith('/uploads/')) {
            deleteFile(listing.imageUrl);
        }
        
        await FoodListing.deleteOne({ _id: req.params.id });
        res.json({ message: 'Listing removed successfully' });
    } catch (error) {
        console.error("Error deleting listing:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
});

app.use(`${API_BASE_URL}/food`, foodRouter);

// --- Admin Routes (/api/admin/...) ---
const adminRouter = express.Router();

// Helper for admin date filters
const getDateFilter = (filterQuery) => {
    const dateFilter = {};
    const now = new Date();
    const fieldToFilter = 'createdAt'; // Filter by creation date
    if (filterQuery === '1week') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setDate(now.getDate() - 7)) };
    else if (filterQuery === '1month') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setMonth(now.getMonth() - 1)) };
    else if (filterQuery === '3month') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setMonth(now.getMonth() - 3)) };
    else if (filterQuery === '1year') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setFullYear(now.getFullYear() - 1)) };
    return dateFilter;
};

/**
 * @route   GET /api/admin/dashboard
 * @desc    Get dashboard stats
 * @access  Private (Admin)
 */
adminRouter.get('/dashboard', protect, admin, async (req, res) => {
    try {
        const { filter } = req.query;
        const dateFilter = getDateFilter(filter);

        const userCount = await User.countDocuments({ role: { $ne: 'Admin' } }); // Exclude admin from count
        const donorCount = await User.countDocuments({ role: 'Donor' });
        const listingCount = await FoodListing.countDocuments(dateFilter);
        
        const activeListings = await FoodListing.countDocuments({
            ...dateFilter,
            expiryTime: { $gt: new Date() },
            $expr: { $lt: [ { $size: "$claims" }, "$maxClaims" ] }
        });

        res.json({
            totalUsers: userCount,
            totalDonors: donorCount,
            totalListings: listingCount,
            activeListings: activeListings
        });
    } catch (error) {
        console.error("Error getting admin dashboard stats:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
});

/**
 * @route   GET /api/admin/users
 * @desc    Get all users
 * @access  Private (Admin)
 */
adminRouter.get('/users', protect, admin, async (req, res) => {
    try {
        // Find all users except the admin themselves, sort by creation date
        const users = await User.find({ role: { $ne: 'Admin' } })
            .select('-password')
            .sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        console.error("Error getting admin users:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
});

/**
 * @route   GET /api/admin/food
 * @desc    Get all listings (with filter)
 * @access  Private (Admin)
 * @UPDATE  Changed from /listings to /food to match frontend
 */
adminRouter.get('/food', protect, admin, async (req, res) => {
    try {
        const { filter } = req.query;
        const dateFilter = getDateFilter(filter);
        const listings = await FoodListing.find(dateFilter).sort({ createdAt: -1 });
        
        res.json(listings.map(transformImageUrl));

    } catch (error) {
        console.error("Error getting admin listings:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
});

/**
 * @route   DELETE /api/admin/food/:id
 * @desc    Delete any listing as Admin
 * @access  Private (Admin)
 * @NEW     Added to match frontend admin delete call
 */
adminRouter.delete('/food/:id', protect, admin, async (req, res) => {
    try {
        const listing = await FoodListing.findById(req.params.id);
        if (!listing) return res.status(404).json({ message: 'Listing not found' });

        // Admin can delete any listing, so no need to check for donor ID

        if (listing.imageUrl && listing.imageUrl.startsWith('/uploads/')) {
            deleteFile(listing.imageUrl);
        }
        
        await FoodListing.deleteOne({ _id: req.params.id });
        res.json({ message: 'Listing removed successfully by admin' });

    } catch (error) {
        console.error("Error deleting listing by admin:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
});


app.use(`${API_BASE_URL}/admin`, adminRouter);

// --- Server Listen ---
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});