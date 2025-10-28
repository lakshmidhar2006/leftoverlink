// --- Imports (ESM Syntax) ---
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
// import multer from 'multer'; // REMOVED MULTER
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { v2 as cloudinary } from 'cloudinary';

// Load environment variables immediately
dotenv.config();

// ESM equivalent for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Configure Cloudinary ---
// Ensure environment variables are loaded before this
if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
    console.error("FATAL ERROR: Cloudinary environment variables are not fully configured.");
    // Optionally exit process: process.exit(1);
} else {
    cloudinary.config({
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET,
        secure: true, // Use HTTPS
    });
    console.log('Cloudinary Configured:', process.env.CLOUDINARY_CLOUD_NAME);
}


// --- App Initialization ---
const app = express();
const PORT = process.env.PORT || 3001;
const API_BASE_URL = '/api';

// --- REMOVED MULTER CONFIG ---

// --- Middleware ---
app.use(cors()); // Consider configuring CORS more restrictively for production
app.use(express.json()); // Handles JSON body including imageUrl and imagePublicId
app.use(express.urlencoded({ extended: true })); // For standard form data if needed elsewhere


// --- Mongoose Schemas & Models ---

// 1. User Schema
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['Donor', 'Receiver', 'Admin'], required: true },
    location: { type: String, trim: true } // Optional: Location for Donor/Receiver
}, { timestamps: true });

// Password Hashing Middleware
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

// Password Comparison Method
UserSchema.methods.comparePassword = function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', UserSchema);

// 2. Food Listing Schema
const FoodListingSchema = new mongoose.Schema({
    donor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, // Added index
    donorName: { type: String, required: true }, // Denormalized for easier display
    description: { type: String, required: true, trim: true },
    quantity: { type: String, required: true, trim: true }, // e.g., "10 packets", "5 kg"
    location: { type: String, required: true, trim: true },
    imageUrl: { type: String, default: null }, // URL from Cloudinary via frontend
    imagePublicId: { type: String, default: null }, // Public ID from Cloudinary via frontend
    mfgTime: { type: Date, required: true },
    expiryTime: { type: Date, required: true, index: true }, // Added index
    maxClaims: { type: Number, required: true, default: 1, min: 1 },
    claims: [
        {
            _id: false, // Don't create separate _id for claims subdocuments
            userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
            name: { type: String, required: true }, // Denormalized user name
            claimTime: { type: Date, default: Date.now }
        }
    ],
    status: { // Calculated or explicit status
        type: String,
        enum: ['Available', 'Fully Claimed', 'Expired'],
        default: 'Available',
        index: true // Index status for faster filtering
    },
}, { timestamps: true }); // Includes createdAt, updatedAt

// Optional: Add index for faster searching by description or location if needed
// FoodListingSchema.index({ description: 'text', location: 'text' });

const FoodListing = mongoose.model('FoodListing', FoodListingSchema);


// --- Admin User Seeding Function ---
const seedAdminUser = async () => {
    try {
        const adminEmail = process.env.ADMIN_EMAIL || "admin@gmail.com";
        const adminPassword = process.env.ADMIN_PASSWORD || "adminbalu";
        const adminName = process.env.ADMIN_NAME || "Admin Sreekruthi";
        const adminExists = await User.findOne({ email: adminEmail });

        if (!adminExists) {
            console.log(`Admin user (${adminEmail}) not found. Creating...`);
            // Hash password before saving
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(adminPassword, salt);
            const adminUser = new User({ name: adminName, email: adminEmail, password: hashedPassword, role: "Admin" });
            await adminUser.save();
            console.log(`Admin user (${adminEmail}) created successfully.`);
        } else {
            console.log(`Admin user (${adminEmail}) already exists.`);
            // Optional: Update existing admin password if needed (use with caution)
            // if (!(await adminExists.comparePassword(adminPassword))) {
            //     console.log(`Updating password for admin user (${adminEmail})...`);
            //     adminExists.password = adminPassword; // Let pre-save hook handle hashing
            //     await adminExists.save();
            //     console.log(`Admin password updated.`);
            // }
        }
    } catch (error) {
        console.error("Error seeding admin user:", error.message);
    }
};

// --- Database Connection ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log("MongoDB connected successfully.");
        seedAdminUser(); // Seed admin user after successful connection
    })
    .catch(err => {
        console.error("MongoDB connection error:", err);
        process.exit(1); // Exit if DB connection fails
    });


// --- Authentication Middleware (protect) ---
const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            // Fetch user and attach necessary fields (id, role, name)
            req.user = await User.findById(decoded.id).select('_id name email role'); // Select needed fields
            if (!req.user) {
                // User might have been deleted after token issuance
                return res.status(401).json({ message: 'Not authorized, user not found' });
            }
            next(); // Proceed if user is found and token is valid
        } catch (error) {
            console.error("Token verification failed:", error.message);
            if (error.name === 'JsonWebTokenError') {
                return res.status(401).json({ message: 'Not authorized, invalid token' });
            } else if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Not authorized, token expired' });
            } else {
                return res.status(401).json({ message: 'Not authorized, token failed' });
            }
        }
    } else {
        res.status(401).json({ message: 'Not authorized, no token provided' });
    }
};

// --- Admin Middleware ---
const admin = (req, res, next) => {
    // Ensure protect middleware ran first and attached user
    if (req.user && req.user.role === 'Admin') {
        next();
    } else {
        res.status(403).json({ message: 'Forbidden: Access restricted to administrators' });
    }
};


// --- Auth Routes (/api/auth/...) ---
const authRouter = express.Router();

authRouter.post('/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    // Basic Input Validation
    if (!name || !email || !password || !role) {
        return res.status(400).json({ message: 'Please enter all fields' });
    }
    if (!['Donor', 'Receiver'].includes(role)) { // Only allow Donor or Receiver registration via API
         return res.status(400).json({ message: 'Invalid role specified for registration' });
    }
    // Prevent registering with admin email or role 'Admin'
    if (role === 'Admin' || (process.env.ADMIN_EMAIL && email.toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase())) {
        return res.status(400).json({ message: 'Registration with this email or role is not allowed.' });
    }

    try {
        const userExists = await User.findOne({ email: email.toLowerCase() });
        if (userExists) {
            return res.status(400).json({ message: 'User with this email already exists' });
        }
        // Password hashing is handled by the pre-save hook in the User model
        const user = new User({ name, email: email.toLowerCase(), password, role });
        await user.save();

        // Generate token
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });

        // Send response
        res.status(201).json({
            token,
            user: { _id: user._id, name: user.name, email: user.email, role: user.role }, // Send back user details (excluding password)
        });
    } catch (error) {
        console.error("Registration error:", error);
        // Handle potential duplicate key error during save (though findOne should catch it)
        if (error.code === 11000) {
            return res.status(400).json({ message: 'User with this email already exists (concurrent registration)' });
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
        const user = await User.findOne({ email: email.toLowerCase() });
        if (user && (await user.comparePassword(password))) {
            const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
            res.json({
                token,
                user: { _id: user._id, name: user.name, email: user.email, role: user.role }, // Return user details
            });
        } else {
            res.status(401).json({ message: 'Invalid email or password' }); // Generic message for security
        }
    } catch (error) {
        console.error("Login server error:", error);
        res.status(500).json({ message: 'Server error during login' });
    }
});
app.use(`${API_BASE_URL}/auth`, authRouter);


// --- Food Listing Routes (/api/food/...) ---
const foodRouter = express.Router();

/**
 * @route   POST /api/food
 * @desc    Create a new food listing (expects imageUrl and imagePublicId in body from frontend upload)
 * @access  Private (Donor)
 */
foodRouter.post('/', protect, async (req, res) => { // REMOVED upload middleware
    if (req.user.role !== 'Donor') {
        return res.status(403).json({ message: 'Forbidden: Only donors can create listings.' });
    }

    // Get ALL data, including image details, from req.body
    const { description, quantity, location, mfgTime, expiryTime, maxClaims, imageUrl, imagePublicId } = req.body;

    // Validate fields
    if (!description || !quantity || !location || !mfgTime || !expiryTime || maxClaims === undefined) { // Check maxClaims for undefined too
        return res.status(400).json({ message: 'Please fill out all required fields.' });
    }
    const parsedMaxClaims = parseInt(maxClaims, 10);
    if (isNaN(parsedMaxClaims) || parsedMaxClaims < 1) {
        return res.status(400).json({ message: 'Maximum claims must be a number greater than 0.' });
    }
    const mfgDate = new Date(mfgTime);
    const expiryDate = new Date(expiryTime);
    if (isNaN(mfgDate.getTime()) || isNaN(expiryDate.getTime())) {
        return res.status(400).json({ message: 'Invalid date format provided.' });
    }
    if (expiryDate <= mfgDate) {
         return res.status(400).json({ message: 'Expiry time must be after manufacture time.' });
    }

    try {
        // NO CLOUDINARY UPLOAD HERE - Frontend did it

        const newListing = new FoodListing({
            donor: req.user._id,
            donorName: req.user.name, // Get name from authenticated user
            description, quantity, location,
            imageUrl: imageUrl || null,         // Use URL from frontend
            imagePublicId: imagePublicId || null, // Use Public ID from frontend
            mfgTime: mfgDate, expiryTime: expiryDate,
            maxClaims: parsedMaxClaims,
            claims: []
            // Status defaults to 'Available'
        });
        const savedListing = await newListing.save();

        res.status(201).json(savedListing.toObject()); // Send saved listing

    } catch (error) {
        console.error("Error creating listing (DB save):", error);
         if (error.name === 'ValidationError') {
             // Extract more specific validation messages if needed
             const messages = Object.values(error.errors).map(val => val.message);
             return res.status(400).json({ message: 'Validation Error', errors: messages });
        }
        res.status(500).json({ message: 'Server error while creating listing' });
    }
});

/**
 * @route   PUT /api/food/:id
 * @desc    Update a food listing (expects optional imageUrl/imagePublicId in body)
 * @access  Private (Donor)
 */
foodRouter.put('/:id', protect, async (req, res) => { // REMOVED upload middleware
    try {
        const listing = await FoodListing.findById(req.params.id);
        if (!listing) return res.status(404).json({ message: 'Listing not found' });

        // Check ownership
        if (listing.donor.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: 'Forbidden: User not authorized to update this listing' });
        }

        // Get updated data, including potentially new image details, from body
        const { description, quantity, location, mfgTime, expiryTime, maxClaims, imageUrl, imagePublicId } = req.body;
        const oldImagePublicId = listing.imagePublicId; // Store old public ID for potential deletion

        // --- NO CLOUDINARY UPLOAD HERE ---

        // Basic validation for updated fields
        let parsedMaxClaims = listing.maxClaims; // Keep old value if not provided
        if (maxClaims !== undefined) {
             parsedMaxClaims = parseInt(maxClaims, 10);
             if (isNaN(parsedMaxClaims) || parsedMaxClaims < 1) {
                 return res.status(400).json({ message: 'Maximum claims must be a number greater than 0.' });
             }
        }
        let mfgDate = listing.mfgTime;
        if (mfgTime !== undefined) {
            mfgDate = new Date(mfgTime);
             if (isNaN(mfgDate.getTime())) return res.status(400).json({ message: 'Invalid manufacture date format.' });
        }
        let expiryDate = listing.expiryTime;
        if (expiryTime !== undefined) {
             expiryDate = new Date(expiryTime);
             if (isNaN(expiryDate.getTime())) return res.status(400).json({ message: 'Invalid expiry date format.' });
        }
        if (expiryDate <= mfgDate) {
              return res.status(400).json({ message: 'Expiry time must be after manufacture time.' });
        }


        // Update fields if they exist in req.body
        if (description !== undefined) listing.description = description;
        if (quantity !== undefined) listing.quantity = quantity;
        if (location !== undefined) listing.location = location;
        if (mfgTime !== undefined) listing.mfgTime = mfgDate;
        if (expiryTime !== undefined) listing.expiryTime = expiryDate;
        if (maxClaims !== undefined) listing.maxClaims = parsedMaxClaims;

        // Update image fields ONLY if they were provided in the request body
        // Allows frontend to send null/empty string to remove image
        let imageUpdated = false;
        if (imageUrl !== undefined) {
             listing.imageUrl = imageUrl || null;
             imageUpdated = true;
        }
        if (imagePublicId !== undefined) {
             listing.imagePublicId = imagePublicId || null;
             imageUpdated = true; // Assume if public ID changes, image changed
        }

        const updatedListing = await listing.save();

        // --- Delete OLD image from Cloudinary if a NEW one was provided OR image was removed ---
        const newImagePublicId = imagePublicId === undefined ? oldImagePublicId : (imagePublicId || null); // Current public ID state
        const oldImageExisted = !!oldImagePublicId;
        const publicIdChangedOrRemoved = oldImagePublicId !== newImagePublicId;

        if (imageUpdated && oldImageExisted && publicIdChangedOrRemoved) {
            console.log(`Image updated or removed. Deleting old image from Cloudinary: ${oldImagePublicId}`);
            try {
                await cloudinary.uploader.destroy(oldImagePublicId);
                 console.log(`Successfully deleted old Cloudinary image: ${oldImagePublicId}`);
            } catch (destroyError) {
                console.error("Error deleting old Cloudinary image during update:", destroyError);
                // Log error but proceed, listing is updated in DB
            }
        }
        // --- End Delete OLD image ---

        res.json(updatedListing.toObject());

    } catch (error) {
        console.error("Error updating listing (DB save):", error);
         if (error.name === 'ValidationError') {
             const messages = Object.values(error.errors).map(val => val.message);
             return res.status(400).json({ message: 'Validation Error', errors: messages });
        }
        res.status(500).json({ message: 'Server error while updating listing' });
    }
});


/**
 * @route   GET /api/food
 * @desc    Get all available listings (for Receivers) - not expired, not fully claimed
 * @access  Private (Authenticated User - Receiver or Donor)
 */
foodRouter.get('/', protect, async (req, res) => {
    try {
        const now = new Date();
        const listings = await FoodListing.find({
            expiryTime: { $gt: now },
            // Check if claims array size is less than maxClaims
            $expr: { $lt: [{ $size: { $ifNull: ["$claims", []] } }, "$maxClaims"] }
            // Optionally exclude donor's own listings if needed (more complex logic)
            // donor: { $ne: req.user._id } // Basic exclusion, might need adjustment
        }).sort({ expiryTime: 1 }); // Sort by soonest expiry

        // Add placeholder image URL if imageUrl is null or empty
        const listingsWithPlaceholder = listings.map(listing => {
            const listingObj = listing.toObject();
            if (!listingObj.imageUrl) {
                listingObj.imageUrl = 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';
            }
             // Ensure claims is an array even if empty
             listingObj.claims = listingObj.claims || [];
            return listingObj;
        });

        res.json(listingsWithPlaceholder);

    } catch (error) {
        console.error("Error getting available listings:", error);
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

        const listingsWithPlaceholder = listings.map(listing => {
            const listingObj = listing.toObject();
            if (!listingObj.imageUrl) {
                 listingObj.imageUrl = 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';
            }
            // Ensure claims is an array even if empty
             listingObj.claims = listingObj.claims || [];
            return listingObj;
        });

        res.json(listingsWithPlaceholder);

    } catch (error) {
        console.error("Error getting donor listings:", error);
        res.status(500).json({ message: 'Server error fetching donor listings' });
    }
});

/**
 * @route   GET /api/food/myclaims
 * @desc    Get listings claimed by the logged-in receiver
 * @access  Private (Receiver)
 */
foodRouter.get('/myclaims', protect, async (req, res) => {
     if (req.user.role !== 'Receiver') {
         return res.status(403).json({ message: 'Forbidden: Only receivers can view their claims.' });
     }
     try {
         // Find listings where the claims array contains an element matching the user's ID
         const listings = await FoodListing.find({ "claims.userId": req.user._id })
             .sort({ createdAt: -1 }); // Or sort by claim time if needed

         const listingsWithPlaceholder = listings.map(listing => {
             const listingObj = listing.toObject();
             if (!listingObj.imageUrl) {
                  listingObj.imageUrl = 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';
             }
              // Ensure claims is an array even if empty
              listingObj.claims = listingObj.claims || [];
             return listingObj;
         });

         res.json(listingsWithPlaceholder);
     } catch (error) {
         console.error("Error getting receiver claims:", error);
         res.status(500).json({ message: 'Server error fetching claims' });
     }
 });


/**
 * @route   POST /api/food/:id/claim
 * @desc    Claim a food listing slot
 * @access  Private (Receiver)
 */
foodRouter.post('/:id/claim', protect, async (req, res) => {
     try {
         if (req.user.role !== 'Receiver') {
             return res.status(403).json({ message: 'Forbidden: Only receivers can claim food.' });
         }
         const listingId = req.params.id;
         const userId = req.user._id;
         const userName = req.user.name; // Get name from authenticated user

         const listing = await FoodListing.findById(listingId);

         // --- Comprehensive Checks ---
         if (!listing) return res.status(404).json({ message: 'Listing not found' });
         if (new Date(listing.expiryTime) < new Date()) return res.status(400).json({ message: 'This listing has expired.' });
         if (listing.donor.toString() === userId.toString()) return res.status(400).json({ message: 'Donors cannot claim their own listing.' });
         if ((listing.claims || []).length >= listing.maxClaims) return res.status(400).json({ message: 'This listing is fully claimed.' });
         const alreadyClaimed = (listing.claims || []).some(claim => claim.userId.toString() === userId.toString());
         if (alreadyClaimed) return res.status(400).json({ message: 'You have already claimed this listing.' });
         // --- End Checks ---

         // Add the claim
         listing.claims.push({ userId: userId, name: userName, claimTime: new Date() });

         // Potentially update status if now fully claimed
         if (listing.claims.length === listing.maxClaims) {
            listing.status = 'Fully Claimed';
         }

         const updatedListing = await listing.save();

         // Add placeholder if needed before sending response
         const listingObj = updatedListing.toObject();
          if (!listingObj.imageUrl) {
              listingObj.imageUrl = 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';
          }
           // Ensure claims is an array even if empty
           listingObj.claims = listingObj.claims || [];
         res.json(listingObj);

     } catch (error) {
         console.error("Error claiming listing:", error);
         // Handle potential race conditions if needed (e.g., using findOneAndUpdate with checks)
         res.status(500).json({ message: 'Server error while claiming listing' });
     }
 });

/**
 * @route   DELETE /api/food/:id
 * @desc    Delete a food listing (Donor only) with Cloudinary delete
 * @access  Private (Donor)
 */
foodRouter.delete('/:id', protect, async (req, res) => {
    try {
        const listing = await FoodListing.findById(req.params.id);
        if (!listing) return res.status(404).json({ message: 'Listing not found' });

        // Check ownership - Only the DONOR can delete via this route
        if (listing.donor.toString() !== req.user._id.toString()) {
            // Admin deletion should use the /api/admin/food/:id route
            return res.status(403).json({ message: 'Forbidden: User not authorized to delete this listing' });
        }

        const publicIdToDelete = listing.imagePublicId; // Get public_id BEFORE deleting doc

        await FoodListing.deleteOne({ _id: req.params.id });

        // --- Delete from Cloudinary ---
        if (publicIdToDelete) {
            console.log(`Listing deleted. Deleting image from Cloudinary: ${publicIdToDelete}`);
            try {
                const result = await cloudinary.uploader.destroy(publicIdToDelete);
                console.log(`Cloudinary deletion result for ${publicIdToDelete}:`, result);
            } catch (destroyError) {
                console.error("Error deleting Cloudinary image during listing delete:", destroyError);
                // Log error but proceed, listing is already deleted from DB
            }
        }
        // --- End Delete from Cloudinary ---

        res.json({ message: 'Listing removed successfully' });
    } catch (error) {
        console.error("Error deleting listing:", error);
        res.status(500).json({ message: 'Server error while deleting listing' });
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

    if (!filterQuery) return dateFilter; // No filter specified

    try {
        if (filterQuery === '1week') dateFilter[fieldToFilter] = { $gte: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000) };
        else if (filterQuery === '1month') dateFilter[fieldToFilter] = { $gte: new Date(now.getFullYear(), now.getMonth() - 1, now.getDate()) };
        else if (filterQuery === '1year') dateFilter[fieldToFilter] = { $gte: new Date(now.getFullYear() - 1, now.getMonth(), now.getDate()) };
    } catch (e) {
        console.error("Error parsing date filter:", e);
        // Return empty filter if parsing fails
    }
    return dateFilter;
};

/**
 * @route   GET /api/admin/dashboard
 * @desc    Get dashboard stats (counts based on optional filter)
 * @access  Private (Admin)
 */
adminRouter.get('/dashboard', protect, admin, async (req, res) => {
    try {
        const { filter } = req.query;
        const dateFilter = getDateFilter(filter); // Filter applies to listings count

        // Get overall counts for users/donors, filtered counts for listings
        const [userCount, donorCount, listingCountFiltered, activeListingCountOverall] = await Promise.all([
            User.countDocuments({ role: { $ne: 'Admin' } }), // Total non-admin users
            User.countDocuments({ role: 'Donor' }), // Total donors
            FoodListing.countDocuments(dateFilter), // Total listings within filter period
            FoodListing.countDocuments({ // Active listings overall (not filtered by date)
                expiryTime: { $gt: new Date() },
                $expr: { $lt: [{ $size: { $ifNull: ["$claims", []] } }, "$maxClaims"] }
            })
        ]);

        res.json({
             totalUsers: userCount,
             totalDonors: donorCount,
             totalListings: listingCountFiltered, // Label clearly that this is filtered
             activeListings: activeListingCountOverall // Label clearly this is overall
        });
    } catch (error) {
        console.error("Error getting admin dashboard stats:", error);
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
        const users = await User.find({ _id: { $ne: req.user._id } }) // Exclude self
            .select('-password') // Exclude password
            .sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        console.error("Error getting admin users:", error);
        res.status(500).json({ message: 'Server error fetching users' });
    }
});

/**
 * @route   GET /api/admin/food
 * @desc    Get all listings (with date filter) for Admin view
 * @access  Private (Admin)
 */
adminRouter.get('/food', protect, admin, async (req, res) => {
     try {
         const { filter } = req.query;
         const dateFilter = getDateFilter(filter);
         const listings = await FoodListing.find(dateFilter).sort({ createdAt: -1 });

         const listingsWithPlaceholder = listings.map(listing => {
             const listingObj = listing.toObject();
             if (!listingObj.imageUrl) {
                  listingObj.imageUrl = 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';
             }
              // Ensure claims is an array even if empty
              listingObj.claims = listingObj.claims || [];
             return listingObj;
         });

         res.json(listingsWithPlaceholder);
     } catch (error) {
         console.error("Error getting admin listings:", error);
         res.status(500).json({ message: 'Server error fetching listings' });
     }
 });

/**
 * @route   DELETE /api/admin/food/:id
 * @desc    Delete ANY listing as Admin with Cloudinary delete
 * @access  Private (Admin)
 */
adminRouter.delete('/food/:id', protect, admin, async (req, res) => {
    // Admin middleware already confirmed user is admin
     try {
        const listing = await FoodListing.findById(req.params.id);
        if (!listing) return res.status(404).json({ message: 'Listing not found' });

        const publicIdToDelete = listing.imagePublicId;

        await FoodListing.deleteOne({ _id: req.params.id });

        if (publicIdToDelete) {
            console.log(`Listing deleted by admin. Deleting image from Cloudinary: ${publicIdToDelete}`);
            try {
                const result = await cloudinary.uploader.destroy(publicIdToDelete);
                console.log(`Cloudinary deletion result for ${publicIdToDelete}:`, result);
            } catch (destroyError) {
                console.error("Error deleting Cloudinary image during admin delete:", destroyError);
            }
        }

        res.json({ message: 'Listing removed successfully by admin' });

    } catch (error) {
        console.error("Error deleting listing by admin:", error);
        res.status(500).json({ message: 'Server error during admin delete' });
    }
});

app.use(`${API_BASE_URL}/admin`, adminRouter);


// -----------------------------------------------------------------
// --- FINAL STEP: SERVE REACT APP & CATCH-ALL ROUTE ---
// -----------------------------------------------------------------
const buildPath = path.join(__dirname, '../client/dist'); // Adjust if your structure differs
console.log(`Attempting to serve static files from: ${buildPath}`);

if (fs.existsSync(buildPath)) {
    // Serve static files from the React build directory
    app.use(express.static(buildPath));
    console.log(`Serving static files from: ${buildPath}`);

    // Handles any requests that don't match the API routes by sending back index.html
    app.get('*', (req, res) => {
        // Important: Only serve index.html for non-API routes
        if (!req.path.startsWith(API_BASE_URL)) {
            res.sendFile(path.resolve(buildPath, 'index.html'), (err) => {
                if (err) {
                    console.error('Error sending index.html:', err);
                    res.status(500).send('Error loading the application.');
                }
            });
        } else {
             // If it's an API route not handled above, send 404
             res.status(404).json({ message: `API endpoint not found: ${req.method} ${req.originalUrl}` });
        }
    });
} else {
    console.warn(`WARN: Frontend build path not found at ${buildPath}.`);
    console.warn("Make sure you have run 'npm run build' in the 'client' directory.");
    console.warn("The frontend app will not be served.");
    // Fallback for API 404s if build doesn't exist
     app.get('/', (req, res) => res.send('Server running. Frontend build missing.'));
     app.use(API_BASE_URL + '/*', (req, res) => {
        res.status(404).json({ message: `API endpoint not found: ${req.method} ${req.originalUrl}` });
    });
}

// --- Global Error Handling Middleware (Keep this last) ---
app.use((err, req, res, next) => {
    console.error("Global Error Handler triggered:", err); // Log the full error
    const statusCode = err.status || 500;
    res.status(statusCode).json({
        message: err.message || 'An unexpected server error occurred.',
        // Optionally include stack trace in development
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
});

// --- Server Listen ---
app.listen(PORT, () => {
    console.log(`-------------------------------------------`);
    console.log(`Server running on port ${PORT}`);
    console.log(`API base URL: ${API_BASE_URL}`);
    if (process.env.RENDER_EXTERNAL_URL) {
        console.log(`Public URL (Render): ${process.env.RENDER_EXTERNAL_URL}`);
    } else {
        console.log(`Public URL (Dev): http://localhost:${PORT}`);
    }
    console.log("Ensure frontend .env points to the correct backend URL.");
    console.log("Ensure backend .env has correct DB, JWT, and Cloudinary credentials.");
    console.log(`Cloudinary Cloud Name: ${process.env.CLOUDINARY_CLOUD_NAME || 'NOT SET'}`);
    console.log(`-------------------------------------------`);
});
