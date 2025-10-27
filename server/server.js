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
// *** Import Cloudinary ***
import { v2 as cloudinary } from 'cloudinary';

// Load environment variables immediately
dotenv.config();

// ESM equivalent for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- *** Configure Cloudinary *** ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true, // Use HTTPS
});
console.log('Cloudinary configured.');


// --- App Initialization ---
const app = express();
const PORT = process.env.PORT || 3001;
const API_BASE_URL = '/api';

// --- *** File Upload Setup (Multer - Using Memory Storage for Cloudinary) *** ---
// REMOVE: const UPLOADS_DIR = path.join(__dirname, 'uploads'); ... fs.mkdirSync ...

const storage = multer.memoryStorage(); // Use memory storage

const upload = multer({
    storage: storage, // Use memory storage
    limits: { fileSize: 1024 * 1024 * 5 }, // 5MB limit still applies
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
// REMOVE: app.use('/uploads', express.static(UPLOADS_DIR)); // Not needed anymore

// --- Mongoose Schemas & Models ---

// 1. User Schema (No changes needed)
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
        console.error("Error during password hashing:", err);
        next(err);
    }
});
UserSchema.methods.comparePassword = function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};
const User = mongoose.model('User', UserSchema);

// 2. Food Listing Schema (imageUrl default changed)
const FoodListingSchema = new mongoose.Schema({
    donor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    donorName: { type: String, required: true },
    description: { type: String, required: true },
    quantity: { type: String, required: true },
    location: { type: String, required: true },
    // *** Default to null, Cloudinary URL will be added if uploaded ***
    imageUrl: { type: String, default: null },
    // *** Store Cloudinary public_id for easy deletion ***
    imagePublicId: { type: String, default: null },
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


// --- Admin User Seeding Function (No changes needed) ---
const seedAdminUser = async () => {
    try {
        const adminEmail = process.env.ADMIN_EMAIL || "admin@gmail.com";
        const adminPassword = process.env.ADMIN_PASSWORD || "adminbalu";
        const adminName = process.env.ADMIN_NAME || "Admin Sreekruthi";
        const adminExists = await User.findOne({ email: adminEmail });

        if (!adminExists) {
            console.log(`Admin user (${adminEmail}) not found. Creating...`);
            const adminUser = new User({ name: adminName, email: adminEmail, password: adminPassword, role: "Admin" });
            await adminUser.save();
            console.log(`Admin user (${adminEmail}) created successfully.`);
        } else {
            console.log(`Admin user (${adminEmail}) already exists.`);
        }
    } catch (error) {
        console.error("Error seeding admin user:", error.message);
    }
};

// --- Database Connection (No changes needed) ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log("MongoDB connected successfully.");
        seedAdminUser();
    })
    .catch(err => console.error("MongoDB connection error:", err));


// --- Authentication Middleware (protect) (No changes needed) ---
const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = await User.findById(decoded.id).select('-password');
            if (!req.user) {
                return res.status(401).json({ message: 'User belonging to this token no longer exists' });
            }
            next();
        } catch (error) {
            console.error("Token verification failed:", error.message);
            if (error.name === 'JsonWebTokenError') {
                 res.status(401).json({ message: 'Not authorized, invalid token' });
            } else if (error.name === 'TokenExpiredError') {
                 res.status(401).json({ message: 'Not authorized, token expired' });
            } else {
                 res.status(401).json({ message: 'Not authorized, token failed' });
            }
        }
    } else {
        res.status(401).json({ message: 'Not authorized, no token provided' });
    }
};

// --- Admin Middleware (No changes needed) ---
const admin = (req, res, next) => {
    if (req.user && req.user.role === 'Admin') {
        next();
    } else {
        res.status(403).json({ message: 'Forbidden: Access restricted to administrators' });
    }
};

// --- REMOVE Helper: deleteFile (Not needed for Cloudinary) ---
// const deleteFile = (...) => { ... };

// --- REMOVE Helper: transformImageUrl (Not needed for Cloudinary) ---
// const transformImageUrl = (...) => { ... };

// --- Auth Routes (/api/auth/...) (No changes needed) ---
const authRouter = express.Router();

authRouter.post('/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
        return res.status(400).json({ message: 'Please enter all fields' });
    }
    if (role === 'Admin' || (process.env.ADMIN_EMAIL && email === process.env.ADMIN_EMAIL)) {
        return res.status(400).json({ message: 'Cannot register with this email or role.' });
    }
    try {
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ message: 'User with this email already exists' });
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
        if (error.code === 11000) {
             return res.status(400).json({ message: 'User with this email already exists' });
        }
        res.status(500).json({ message: 'Server error during registration' });
    }
});

authRouter.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Please enter both email and password' });
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
            res.status(401).json({ message: 'Invalid email or password' });
        }
    } catch (error) {
        console.error("Login server error:", error.message);
        res.status(500).json({ message: 'Server error during login' });
    }
});
app.use(`${API_BASE_URL}/auth`, authRouter);


// --- Food Listing Routes (/api/food/...) ---
const foodRouter = express.Router();

/**
 * @route   POST /api/food
 * @desc    Create a new food listing with Cloudinary upload
 * @access  Private (Donor)
 */
foodRouter.post('/', protect, upload.single('image'), async (req, res) => {
    if (req.user.role !== 'Donor') {
        return res.status(403).json({ message: 'Forbidden: Only donors can create listings.' });
    }

    const { description, quantity, location, mfgTime, expiryTime, maxClaims } = req.body;
    let imageUrl = null;
    let imagePublicId = null;

    // Validate fields
    if (!description || !quantity || !location || !mfgTime || !expiryTime || !maxClaims) {
        return res.status(400).json({ message: 'Please fill out all required fields.' });
    }
    const parsedMaxClaims = parseInt(maxClaims, 10);
    if (isNaN(parsedMaxClaims) || parsedMaxClaims < 1) {
        return res.status(400).json({ message: 'Maximum claims must be a number greater than 0.' });
    }

    try {
        // --- Cloudinary Upload ---
        if (req.file) {
            console.log('Uploading image to Cloudinary...');
            // Convert buffer to data URI
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            let dataURI = `data:${req.file.mimetype};base64,${b64}`;

            // Upload to Cloudinary
            const result = await cloudinary.uploader.upload(dataURI, {
                folder: "leftoverlink", // Optional folder in Cloudinary
                // resource_type: 'auto', // Let Cloudinary detect file type
            });
            imageUrl = result.secure_url; // Use the secure HTTPS URL
            imagePublicId = result.public_id; // Store public_id for deletion
            console.log('Cloudinary upload successful:', imageUrl);
        }
        // --- End Cloudinary Upload ---

        const newListing = new FoodListing({
            donor: req.user._id,
            donorName: req.user.name,
            description, quantity, location,
            imageUrl: imageUrl, // Save Cloudinary URL or null
            imagePublicId: imagePublicId, // Save Cloudinary public_id or null
            mfgTime, expiryTime,
            maxClaims: parsedMaxClaims,
            claims: []
        });
        const savedListing = await newListing.save();

        res.status(201).json(savedListing.toObject()); // Send saved listing

    } catch (error) {
        console.error("Error creating listing (Cloudinary):", error);
        // If Cloudinary upload succeeded but DB save failed, delete the image from Cloudinary
         if (imagePublicId) {
            console.log(`DB save failed after Cloudinary upload. Deleting image: ${imagePublicId}`);
            try {
                await cloudinary.uploader.destroy(imagePublicId);
            } catch (destroyError) {
                 console.error("Error deleting Cloudinary image during cleanup:", destroyError);
            }
         }
        res.status(500).json({ message: 'Server error while creating listing' });
    }
});

/**
 * @route   PUT /api/food/:id
 * @desc    Update a food listing with Cloudinary upload/delete
 * @access  Private (Donor)
 */
foodRouter.put('/:id', protect, upload.single('image'), async (req, res) => {
    try {
        const listing = await FoodListing.findById(req.params.id);
        if (!listing) return res.status(404).json({ message: 'Listing not found' });

        if (listing.donor.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: 'Forbidden: User not authorized to update this listing' });
        }

        const { description, quantity, location, mfgTime, expiryTime, maxClaims } = req.body;
        let oldImagePublicId = listing.imagePublicId; // Store old public ID
        let newImageUrl = listing.imageUrl; // Keep old URL unless new image uploaded
        let newImagePublicId = listing.imagePublicId; // Keep old public ID unless new image uploaded


        // --- Cloudinary Upload (if new image provided) ---
        if (req.file) {
             console.log('Uploading new image to Cloudinary for update...');
             const b64 = Buffer.from(req.file.buffer).toString("base64");
             let dataURI = `data:${req.file.mimetype};base64,${b64}`;
             const result = await cloudinary.uploader.upload(dataURI, {
                 folder: "leftoverlink",
             });
             newImageUrl = result.secure_url;
             newImagePublicId = result.public_id;
             console.log('Cloudinary update upload successful:', newImageUrl);
        }
        // --- End Cloudinary Upload ---

        // Update fields if they exist
        if (description !== undefined) listing.description = description;
        if (quantity !== undefined) listing.quantity = quantity;
        if (location !== undefined) listing.location = location;
        if (mfgTime !== undefined) listing.mfgTime = mfgTime;
        if (expiryTime !== undefined) listing.expiryTime = expiryTime;
        if (maxClaims !== undefined) {
             const parsedMaxClaims = parseInt(maxClaims, 10);
             if (!isNaN(parsedMaxClaims) && parsedMaxClaims >= 1) {
                 listing.maxClaims = parsedMaxClaims;
             }
        }
        // Update image fields only if a new image was uploaded
         if (req.file) {
            listing.imageUrl = newImageUrl;
            listing.imagePublicId = newImagePublicId;
         }

        const updatedListing = await listing.save();

        // --- Delete OLD image from Cloudinary ---
        // Check if a new image was uploaded successfully AND there was an old image
        if (req.file && oldImagePublicId) {
             console.log(`New image uploaded. Deleting old image from Cloudinary: ${oldImagePublicId}`);
             try {
                await cloudinary.uploader.destroy(oldImagePublicId);
             } catch (destroyError) {
                  console.error("Error deleting old Cloudinary image during update:", destroyError);
             }
        }
        // --- End Delete OLD image ---

        res.json(updatedListing.toObject());

    } catch (error) {
        console.error("Error updating listing (Cloudinary):", error);
        // If Cloudinary upload succeeded but DB save failed, delete the NEWLY uploaded image
        if (req.file && error.name !== 'NotFoundError') { // Check if the error wasn't simply 'Listing not found'
            const tempNewPublicId = error.cloudinaryPublicId || (req.file ? `leftoverlink/${req.file.filename}` : null); // Attempt to reconstruct or get from error context if possible
            if (tempNewPublicId){ // Be cautious here
                 console.log(`Error during PUT after new Cloudinary upload. Attempting to delete new image: ${tempNewPublicId}`);
                 try {
                     await cloudinary.uploader.destroy(tempNewPublicId);
                 } catch (destroyError) {
                      console.error("Error deleting newly uploaded Cloudinary image during PUT cleanup:", destroyError);
                 }
            }
        }
        res.status(500).json({ message: 'Server error while updating listing' });
    }
});


/**
 * @route   GET /api/food
 * @desc    Get all available listings (for Receivers)
 * @access  Private (Authenticated)
 */
foodRouter.get('/', protect, async (req, res) => {
    try {
        const listings = await FoodListing.find({
            expiryTime: { $gt: new Date() },
            $expr: { $lt: [{ $size: "$claims" }, "$maxClaims"] }
        }).sort({ expiryTime: 1 });

        // Add placeholder image URL if imageUrl is null
        const listingsWithPlaceholder = listings.map(listing => {
            const listingObj = listing.toObject();
            if (!listingObj.imageUrl) {
                listingObj.imageUrl = 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';
            }
            return listingObj;
        });

        res.json(listingsWithPlaceholder);

    } catch (error) {
        console.error("Error getting available listings:", error.message);
        res.status(500).json({ message: 'Server error fetching listings' });
    }
});

/**
 * @route   GET /api/food/donor/me
 * @desc    Get all of the logged-in donor's own listings
 * @access  Private (Donor)
 */
foodRouter.get('/donor/me', protect, async (req, res) => {
    if (req.user.role !== 'Donor') {
        return res.status(403).json({ message: 'Forbidden: Only donors can view their listings.' });
    }
    try {
        const listings = await FoodListing.find({ donor: req.user._id }).sort({ createdAt: -1 });

        // Add placeholder image URL if imageUrl is null
        const listingsWithPlaceholder = listings.map(listing => {
            const listingObj = listing.toObject();
            if (!listingObj.imageUrl) {
                listingObj.imageUrl = 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';
            }
            return listingObj;
        });

        res.json(listingsWithPlaceholder);

    } catch (error) {
        console.error("Error getting donor listings:", error.message);
        res.status(500).json({ message: 'Server error fetching donor listings' });
    }
});

/**
 * @route   GET /api/food/myclaims
 * @desc    Get listings claimed by receiver
 * @access  Private (Receiver)
 */
foodRouter.get('/myclaims', protect, async (req, res) => {
     if (req.user.role !== 'Receiver') {
         return res.status(403).json({ message: 'Forbidden: Only receivers can view their claims.' });
     }
     try {
         const listings = await FoodListing.find({ "claims.userId": req.user._id })
            .sort({ createdAt: -1 });

         const listingsWithPlaceholder = listings.map(listing => {
             const listingObj = listing.toObject();
             if (!listingObj.imageUrl) {
                 listingObj.imageUrl = 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';
             }
             return listingObj;
         });

         res.json(listingsWithPlaceholder);
     } catch (error) {
         console.error("Error getting receiver claims:", error.message);
         res.status(500).json({ message: 'Server error fetching claims' });
     }
});

/**
 * @route   POST /api/food/:id/claim
 * @desc    Claim a food listing
 * @access  Private (Receiver)
 */
foodRouter.post('/:id/claim', protect, async (req, res) => {
    try {
        if (req.user.role !== 'Receiver') {
            return res.status(403).json({ message: 'Forbidden: Only receivers can claim food.' });
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
        listing.claims.push({ userId: req.user._id, name: req.user.name });
        const updatedListing = await listing.save();

        // Add placeholder if needed before sending response
        const listingObj = updatedListing.toObject();
         if (!listingObj.imageUrl) {
             listingObj.imageUrl = 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';
         }

        res.json(listingObj);
    } catch (error) {
        console.error("Error claiming listing:", error.message);
        res.status(500).json({ message: 'Server error while claiming listing' });
    }
});

/**
 * @route   DELETE /api/food/:id
 * @desc    Delete a food listing (Donor or Admin) with Cloudinary delete
 * @access  Private (Donor or Admin)
 */
foodRouter.delete('/:id', protect, async (req, res) => {
    try {
        const listing = await FoodListing.findById(req.params.id);
        if (!listing) return res.status(404).json({ message: 'Listing not found' });

        if (listing.donor.toString() !== req.user._id.toString() && req.user.role !== 'Admin') {
            return res.status(403).json({ message: 'Forbidden: User not authorized to delete this listing' });
        }

        const publicIdToDelete = listing.imagePublicId; // Get public_id before deleting doc

        await FoodListing.deleteOne({ _id: req.params.id });

        // --- Delete from Cloudinary ---
        if (publicIdToDelete) {
            console.log(`Listing deleted. Deleting image from Cloudinary: ${publicIdToDelete}`);
            try {
                 await cloudinary.uploader.destroy(publicIdToDelete);
            } catch (destroyError) {
                  console.error("Error deleting Cloudinary image during listing delete:", destroyError);
                  // Log error but proceed, listing is already deleted from DB
            }
        }
        // --- End Delete from Cloudinary ---

        res.json({ message: 'Listing removed successfully' });
    } catch (error) {
        console.error("Error deleting listing (Cloudinary):", error.message);
        res.status(500).json({ message: 'Server error while deleting listing' });
    }
});

app.use(`${API_BASE_URL}/food`, foodRouter);


// --- Admin Routes (/api/admin/...) ---
const adminRouter = express.Router();

// Helper for admin date filters (No changes needed)
const getDateFilter = (filterQuery) => {
    const dateFilter = {};
    const now = new Date();
    const fieldToFilter = 'createdAt';
    if (filterQuery === '1week') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setDate(now.getDate() - 7)) };
    else if (filterQuery === '1month') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setMonth(now.getMonth() - 1)) };
    // else if (filterQuery === '3month') dateFilter[fieldToFilter] = { $gte: new Date(new Date().setMonth(now.getMonth() - 3)) };
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

        const [userCount, donorCount, listingCount, activeListings] = await Promise.all([
            User.countDocuments({ role: { $ne: 'Admin' } }),
            User.countDocuments({ role: 'Donor' }),
            FoodListing.countDocuments(dateFilter),
            FoodListing.countDocuments({
                ...dateFilter,
                expiryTime: { $gt: new Date() },
                $expr: { $lt: [{ $size: "$claims" }, "$maxClaims"] }
            })
        ]);

        res.json({ totalUsers: userCount, totalDonors: donorCount, totalListings: listingCount, activeListings: activeListings });
    } catch (error) {
        console.error("Error getting admin dashboard stats:", error.message);
        res.status(500).json({ message: 'Server error fetching dashboard stats' });
    }
});

/**
 * @route   GET /api/admin/users
 * @desc    Get all users (excluding requesting admin)
 * @access  Private (Admin)
 */
adminRouter.get('/users', protect, admin, async (req, res) => {
    try {
        const users = await User.find({ _id: { $ne: req.user._id } })
            .select('-password')
            .sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        console.error("Error getting admin users:", error.message);
        res.status(500).json({ message: 'Server error fetching users' });
    }
});

/**
 * @route   GET /api/admin/food
 * @desc    Get all listings (with filter) for Admin
 * @access  Private (Admin)
 */
adminRouter.get('/food', protect, admin, async (req, res) => {
    try {
        const { filter } = req.query;
        const dateFilter = getDateFilter(filter);
        const listings = await FoodListing.find(dateFilter).sort({ createdAt: -1 });

        // Add placeholder image URL if imageUrl is null
        const listingsWithPlaceholder = listings.map(listing => {
            const listingObj = listing.toObject();
            if (!listingObj.imageUrl) {
                listingObj.imageUrl = 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';
            }
            return listingObj;
        });

        res.json(listingsWithPlaceholder);

    } catch (error) {
        console.error("Error getting admin listings:", error.message);
        res.status(500).json({ message: 'Server error fetching listings' });
    }
});

/**
 * @route   DELETE /api/admin/food/:id
 * @desc    Delete any listing as Admin with Cloudinary delete
 * @access  Private (Admin)
 */
adminRouter.delete('/food/:id', protect, admin, async (req, res) => {
    try {
        const listing = await FoodListing.findById(req.params.id);
        if (!listing) return res.status(404).json({ message: 'Listing not found' });

        const publicIdToDelete = listing.imagePublicId; // Get before deleting doc

        await FoodListing.deleteOne({ _id: req.params.id });

        // --- Delete from Cloudinary ---
        if (publicIdToDelete) {
             console.log(`Listing deleted by admin. Deleting image from Cloudinary: ${publicIdToDelete}`);
             try {
                 await cloudinary.uploader.destroy(publicIdToDelete);
             } catch (destroyError) {
                  console.error("Error deleting Cloudinary image during admin delete:", destroyError);
             }
        }
        // --- End Delete from Cloudinary ---

        res.json({ message: 'Listing removed successfully by admin' });

    } catch (error) {
        console.error("Error deleting listing by admin (Cloudinary):", error.message);
        res.status(500).json({ message: 'Server error during admin delete' });
    }
});

app.use(`${API_BASE_URL}/admin`, adminRouter);


// -----------------------------------------------------------------
// --- FINAL STEP: SERVE REACT APP & CATCH-ALL ROUTE ---
// -----------------------------------------------------------------
const buildPath = path.join(__dirname, '../client/dist');
console.log(`Attempting to serve static files from: ${buildPath}`);

if (fs.existsSync(buildPath)) {
    app.use(express.static(buildPath));
    console.log(`Serving static files from: ${buildPath}`);

    app.get('*', (req, res) => {
        if (!req.path.startsWith(API_BASE_URL)) {
            res.sendFile(path.resolve(buildPath, 'index.html'), (err) => {
                 if (err) {
                      console.error('Error sending index.html:', err);
                      res.status(500).send('Error loading the application.');
                 }
            });
        } else {
             res.status(404).json({ message: "API endpoint not found" });
        }
    });
} else {
    console.warn(`WARN: Frontend build path not found at ${buildPath}. The frontend app will not be served.`);
    app.get('/', (req, res) => {
        res.send('Server is running, but the frontend build directory is missing.');
    });
     app.use(API_BASE_URL + '/*', (req, res) => {
          res.status(404).json({ message: "API endpoint not found" });
     })
}

// --- Server Listen ---
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log("Reminder: Ensure project is NOT in a cloud-synced folder (like OneDrive) during local development.");
    console.log(`API base URL: ${API_BASE_URL}`);
    if (process.env.RENDER_EXTERNAL_URL) {
        console.log(`Public URL (Render): ${process.env.RENDER_EXTERNAL_URL}`);
    } else if (process.env.BASE_URL) {
         console.log(`Public URL (Custom): ${process.env.BASE_URL}`);
    } else {
         console.log(`Public URL (Dev): http://localhost:${PORT}`);
    }
});