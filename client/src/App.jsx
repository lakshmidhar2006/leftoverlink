import React, {
    useState,
    useEffect,
    createContext,
    useContext,
    useMemo,
    useRef,
    useCallback,
} from 'react';
// --- CSS Import ---
// Ensure App.css is located in the same directory as App.jsx, or adjust the path.
// For example, if App.jsx is in src/ and App.css is in src/, use "./App.css"
// If App.css is in src/styles/, use "./styles/App.css"
import "./App.css";
// --- End CSS Import ---

import {
    Routes,
    Route,
    Link,
    useNavigate,
    useLocation,
    Navigate,
} from 'react-router-dom';
import {
    motion,
    AnimatePresence,
} from 'framer-motion';
import {
    Users, Package, CheckCircle, LogIn, LogOut, UserPlus, LayoutDashboard,
    PlusCircle, Trash2, AlertCircle, X, Loader2, UtensilsCrossed, HeartHandshake,
    CalendarDays, MapPin, List, Users2, ClipboardList, Edit3, Download, ImageOff
} from 'lucide-react';

// --- External Libraries ---
// IMPORTANT: Make sure you have installed these libraries:
// npm install jspdf jspdf-autotable
// or
// yarn add jspdf jspdf-autotable
import jsPDF from 'jspdf';
import 'jspdf-autotable';
// --- End External Libraries ---

// --- HARD-CODED VALUES ---
// We are hard-coding these to bypass any .env or Vercel issues
const BACKEND_URL = 'https://leftoverlink-3.onrender.com/api';
const CLOUDINARY_CLOUD_NAME = 'dox0hqyhh';
const CLOUDINARY_UPLOAD_PRESET = 'leftoverlink_preset';
// --- END HARD-CODED VALUES ---


// --- CRITICAL DEBUGGING ---
console.log("--- VERCEL DEPLOYMENT DEBUG ---");
console.log("BACKEND_URL:", BACKEND_URL);
console.log("CLOUDINARY_CLOUD_NAME:", CLOUDINARY_CLOUD_NAME);
console.log("CLOUDINARY_UPLOAD_PRESET:", CLOUDINARY_UPLOAD_PRESET);
// --- END DEBUGGING ---

if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_UPLOAD_PRESET) {
    console.warn(
        "CRITICAL: CLOUDINARY_CLOUD_NAME or CLOUDINARY_UPLOAD_PRESET are not set! This should not happen with hard-coding."
    );
}

// --- Authentication Context ---
const AuthContext = createContext(null);

function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(() => localStorage.getItem('token')); // Initialize from localStorage directly
    const [role, setRole] = useState(() => localStorage.getItem('role')); // Initialize from localStorage directly
    const [isLoading, setIsLoading] = useState(true); // Start true until checked
    const navigate = useNavigate();

    // Redirect logic
    const redirectToDashboard = useCallback((userRole) => {
        console.log("Redirecting based on role:", userRole);
        if (userRole === 'Admin') navigate('/admin', { replace: true });
        else if (userRole === 'Donor') navigate('/donor', { replace: true });
        else if (userRole === 'Receiver') navigate('/receiver', { replace: true });
        else navigate('/login', { replace: true }); // Fallback to login
    }, [navigate]);

    // Logout logic
    const logout = useCallback(() => {
        console.log("Logging out...");
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        localStorage.removeItem('role');
        setToken(null);
        setUser(null);
        setRole(null);
        navigate('/login', { replace: true });
    }, [navigate]);

    // Check localStorage on initial load
    useEffect(() => {
        console.log("AuthProvider useEffect: Checking token...");
        const storedToken = localStorage.getItem('token');
        const storedUser = localStorage.getItem('user');
        const storedRole = localStorage.getItem('role'); // Also check role stored separately if needed

        if (storedToken && storedUser) {
            try {
                const parsedUser = JSON.parse(storedUser);
                setToken(storedToken);
                setUser(parsedUser);
                // Ensure role state matches parsedUser role, or use storedRole if more reliable
                setRole(parsedUser.role || storedRole);
                console.log("User loaded from storage:", parsedUser.email, parsedUser.role);
            } catch (e) {
                console.error("Failed to parse stored user, logging out:", e);
                // Clear potentially corrupted storage
                localStorage.removeItem('token');
                localStorage.removeItem('user');
                localStorage.removeItem('role');
                // Don't call logout() here to avoid navigation loop if logout itself fails
                setToken(null); setUser(null); setRole(null);
            }
        } else {
            console.log("No token/user in storage.");
            // Ensure state is null if nothing in storage
            setToken(null); setUser(null); setRole(null);
        }
        setIsLoading(false); // Finished initial check
    }, []); // Removed logout dependency to prevent potential loops

    // API calls for login/register
    const apiLogin = async (email, password) => {
        const response = await fetch(`${BACKEND_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Login failed');
        return data;
    };

    const apiRegister = async (name, email, password, role) => {
        const response = await fetch(`${BACKEND_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password, role }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Registration failed');
        return data;
    };

    // Login function
    const login = useCallback(async (email, password) => {
        console.log("Attempting login for:", email);
        const { token: receivedToken, user: receivedUser } = await apiLogin(email, password);
        localStorage.setItem('token', receivedToken);
        localStorage.setItem('user', JSON.stringify(receivedUser));
        localStorage.setItem('role', receivedUser.role); // Store role separately too
        setToken(receivedToken);
        setUser(receivedUser);
        setRole(receivedUser.role);
        console.log("Login successful, redirecting...");
        redirectToDashboard(receivedUser.role);
    }, [redirectToDashboard]);

    // Register function
    const register = useCallback(async (name, email, password, role) => {
        console.log("Attempting registration for:", email, role);
        const { token: receivedToken, user: receivedUser } = await apiRegister(name, email, password, role);
        localStorage.setItem('token', receivedToken);
        localStorage.setItem('user', JSON.stringify(receivedUser));
        localStorage.setItem('role', receivedUser.role); // Store role separately too
        setToken(receivedToken);
        setUser(receivedUser);
        setRole(receivedUser.role);
        console.log("Registration successful, redirecting...");
        redirectToDashboard(receivedUser.role);
    }, [redirectToDashboard]);

    // Memoized context value
    const value = useMemo(
        () => ({
            user, token, role, isLoggedIn: !!token, isLoading,
            login, logout, register,
        }),
        [user, token, role, isLoading, login, logout, register]
    );

    return (
        <AuthContext.Provider value={value}>
            {children} {/* Render children immediately, ProtectedRoute will handle loading state */}
        </AuthContext.Provider>
    );
}

// Custom hook to use Auth context
function useAuth() {
    const context = useContext(AuthContext);
    if (!context) throw new Error('useAuth must be used within an AuthProvider');
    return context;
}

// --- Main App Component ---
export default function App() {
    const location = useLocation(); // Needed for AnimatePresence with Routes

    return (
        <AuthProvider> {/* AuthProvider now wraps everything */}
            <Header />
            <main>
                <AnimatePresence mode="wait">
                    {/* Routes component needs location and key for AnimatePresence */}
                    <Routes location={location} key={location.pathname}>
                        {/* Public Routes */}
                        <Route path="/login" element={<GuestRoute><LoginPage /></GuestRoute>} />
                        <Route path="/register" element={<GuestRoute><RegisterPage /></GuestRoute>} />

                        {/* Protected Routes */}
                        <Route path="/donor" element={<ProtectedRoute allowedRoles={['Donor']}><DonorDashboard /></ProtectedRoute>} />
                        <Route path="/receiver" element={<ProtectedRoute allowedRoles={['Receiver']}><ReceiverDashboard /></ProtectedRoute>} />
                        <Route path="/admin" element={<ProtectedRoute allowedRoles={['Admin']}><AdminDashboard /></ProtectedRoute>} />

                        {/* Root path navigation */}
                        <Route path="/" element={<RootNavigation />} />

                        {/* Catch-all - Navigate to root, which will then redirect */}
                        <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                </AnimatePresence>
            </main>
        </AuthProvider>
    );
}

// --- Route Handling Components ---

// Redirects authenticated users away from login/register
function GuestRoute({ children }) {
    const { isLoggedIn, isLoading, role } = useAuth();

    if (isLoading) {
        return <LoadingSpinner />;
    }

    if (isLoggedIn) {
        // Redirect based on role if logged in
        if (role === 'Admin') return <Navigate to="/admin" replace />;
        if (role === 'Donor') return <Navigate to="/donor" replace />;
        if (role === 'Receiver') return <Navigate to="/receiver" replace />;
        // Fallback if role is somehow invalid but logged in
        return <Navigate to="/" replace />;
    }

    // Render the guest page (Login/Register) if not logged in
    return children;
}

// Protects routes based on login status and role
function ProtectedRoute({ children, allowedRoles }) {
    const { isLoggedIn, role, isLoading } = useAuth();
    const location = useLocation();

    if (isLoading) {
        console.log("ProtectedRoute: Auth loading...");
        return <LoadingSpinner />;
    }

    if (!isLoggedIn) {
        console.log("ProtectedRoute: Not logged in, redirecting to login.");
        // Redirect to login, saving the intended destination
        return <Navigate to="/login" state={{ from: location }} replace />;
    }

    if (allowedRoles && !allowedRoles.includes(role)) {
        console.log(`ProtectedRoute: Role mismatch (User: ${role}, Allowed: ${allowedRoles}). Redirecting.`);
        // User is logged in but wrong role, redirect to their default dashboard or root
        if (role === 'Admin') return <Navigate to="/admin" replace />;
        if (role === 'Donor') return <Navigate to="/donor" replace />;
        if (role === 'Receiver') return <Navigate to="/receiver" replace />;
        // Fallback redirect if role doesn't match any standard dashboard
        return <Navigate to="/" replace />;
    }

    // If logged in and role matches (or no specific role required), render the child component
    console.log("ProtectedRoute: Access granted.");
    return children;
}

// Handles navigation from the root path '/'
function RootNavigation() {
    const { isLoggedIn, role, isLoading } = useAuth();

    if (isLoading) {
        return <LoadingSpinner />; // Show loading while checking auth state
    }

    // Determine where to navigate based on login status and role
    if (isLoggedIn) {
        if (role === 'Admin') return <Navigate to="/admin" replace />;
        if (role === 'Donor') return <Navigate to="/donor" replace />;
        if (role === 'Receiver') return <Navigate to="/receiver" replace />;
        // If logged in but role is unknown/invalid, maybe default to login or a generic page
        console.warn("RootNavigation: Logged in but unknown role:", role);
        return <Navigate to="/login" replace />; // Default to login if role issue
    } else {
        // If not logged in, navigate to login page
        return <Navigate to="/login" replace />;
    }
}
// --- Reusable UI Components ---
function PageWrapper({ children }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
            className="page-wrapper" // Ensure this class exists in App.css
        >
            {children}
        </motion.div>
    );
}

function AuthCard({ title, children }) {
    return (
        <div className="auth-page-wrapper"> {/* Ensure this class exists in App.css */}
            <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="auth-card" // Ensure this class exists in App.css
            >
                <div className="auth-card-header">
                    <motion.div
                        animate={{ rotate: [0, 15, -10, 15, 0] }}
                        transition={{ duration: 1, delay: 0.2 }}
                        className="auth-card-icon" // Ensure this class exists in App.css
                    >
                        <HeartHandshake style={{ height: '100%', width: '100%' }} />
                    </motion.div>
                    <h2 className="auth-card-title">{title}</h2> {/* Ensure this class exists */}
                </div>
                {children}
            </motion.div>
        </div>
    );
}

const Input = React.forwardRef(({ id, name, type, placeholder, ...props }, ref) => (
    <div>
        <label htmlFor={id} className="sr-only">{placeholder}</label>
        <input ref={ref} id={id} name={name} type={type} required className="form-input" placeholder={placeholder} {...props} /> {/* Ensure class exists */}
    </div>
));
Input.displayName = 'Input';

const Select = React.forwardRef(({ id, name, children, ...props }, ref) => (
    <div>
        <label htmlFor={id} className="sr-only">{name}</label>
        <select ref={ref} id={id} name={name} required className="form-select" {...props}> {/* Ensure class exists */}
            {children}
        </select>
    </div>
));
Select.displayName = 'Select';

function Button({ children, type = 'button', onClick, disabled = false, className = '', isLoading = false, ...props }) {
    return (
        <motion.button
            type={type}
            onClick={onClick}
            disabled={isLoading || disabled}
            className={`button ${className} ${disabled ? 'button-disabled' : ''}`} // Ensure classes exist
            whileHover={!disabled ? { scale: 1.03, transition: { duration: 0.2 } } : {}}
            whileTap={!disabled ? { scale: 0.98 } : {}}
            {...props}
        >
            {isLoading ? <Loader2 className="spinner-inline" /> : children} {/* Ensure class exists */}
        </motion.button>
    );
}

function Header() {
    const { isLoggedIn, role, logout, user } = useAuth();
    const navigate = useNavigate();
    return (
        <nav className="header-nav"> {/* Ensure classes exist */}
            <div className="header-container">
                <div className="header-logo">
                    <Link to="/" className="header-logo-link">
                        <UtensilsCrossed className="header-logo-icon" />
                        <span className="header-logo-text">LeftoverLink</span>
                    </Link>
                </div>
                <div className="header-links">
                    {isLoggedIn ? (
                        <>
                            <span className="header-user-greeting">Hi, <span>{user?.name || 'User'}</span> {role === 'Admin' && '(Admin)'}</span>
                            {/* Conditional Dashboard Link based on Role */}
                            <HeaderButton
                                onClick={() => {
                                    if (role === 'Admin') navigate('/admin');
                                    else if (role === 'Donor') navigate('/donor');
                                    else if (role === 'Receiver') navigate('/receiver');
                                    else navigate('/'); // Fallback
                                }}
                                icon={<LayoutDashboard className="header-button-icon" />}
                            >
                                Dashboard
                            </HeaderButton>
                            <HeaderButton onClick={logout} icon={<LogOut className="header-button-icon" />} className="logout">Logout</HeaderButton>
                        </>
                    ) : (
                        <>
                            <HeaderButton onClick={() => navigate('/login')} icon={<LogIn className="header-button-icon" />}>Login</HeaderButton>
                            <HeaderButton onClick={() => navigate('/register')} icon={<UserPlus className="header-button-icon" />} className="register">Register</HeaderButton>
                        </>
                    )}
                </div>
            </div>
        </nav>
    );
}

function HeaderButton({ children, onClick, icon, className = '' }) {
    return (
        <motion.button
            onClick={onClick}
            className={`header-button ${className}`} // Ensure classes exist
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
        >
            {icon}<span>{children}</span>
        </motion.button>
    );
}

function ErrorMessage({ message, onDismiss }) {
    if (!message) return null;
    return (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="message-base error-message" role="alert"> {/* Ensure classes exist */}
            <div className="message-content"><AlertCircle className="message-icon" /><span>{message}</span></div>
            {onDismiss && <button onClick={onDismiss} className="message-dismiss-button"><X className="message-icon" /></button>}
        </motion.div>
    );
}

function SuccessMessage({ message, onDismiss }) {
    if (!message) return null;
    return (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="message-base success-message" role="alert"> {/* Ensure classes exist */}
            <div className="message-content"><CheckCircle className="message-icon" /><span>{message}</span></div>
            {onDismiss && <button onClick={onDismiss} className="message-dismiss-button"><X className="message-icon" /></button>}
        </motion.div>
    );
}

function LoadingSpinner() { return <div className="spinner-page-wrapper"><Loader2 className="spinner-page" /></div>; } // Ensure classes exist

// --- API Helper Hook (Removed formFetch) ---
function useApi() {
    const { token, logout } = useAuth();

    // Updated handleResponse to better handle non-JSON or error responses
    const handleResponse = useCallback(async (response) => {
        if (response.status === 401) {
            logout();
            throw new Error('Your session has expired. Please log in again.');
        }

        const contentType = response.headers.get("content-type");
        let dataOrError;

        try {
            if (contentType && contentType.includes("application/json")) {
                dataOrError = await response.json();
            } else {
                // Handle non-JSON responses (like plain text errors from server)
                dataOrError = await response.text();
                // If response is OK but not JSON, return the text (or handle as needed)
                if (response.ok) return dataOrError || {}; // Return text or empty object for success
                // If response is NOT ok and not JSON, create an error from text
                throw new Error(dataOrError || `HTTP error! status: ${response.status}`);
            }
        } catch (e) {
            // Catch JSON parsing errors specifically
            console.error("Failed to parse response:", e);
            if (!response.ok) {
                throw new Error(`API error (${response.status}) with invalid response format.`);
            }
            // If response IS ok but JSON parsing failed (e.g., empty response body), return empty object
            return {};
        }

        if (!response.ok) {
            // Throw error using message from JSON if available, otherwise use status text
            throw new Error(dataOrError.message || response.statusText || 'An API error occurred');
        }

        return dataOrError; // Return parsed JSON data on success
    }, [logout]);


    // Only jsonFetch is needed now
    const jsonFetch = useCallback(async (endpoint, options = {}) => {
        const headers = { 'Content-Type': 'application/json', ...options.headers };
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        console.log(`API Call: ${options.method || 'GET'} ${BACKEND_URL}${endpoint}`); // Log API calls
        const response = await fetch(`${BACKEND_URL}${endpoint}`, { ...options, headers });
        return handleResponse(response);
    }, [token, handleResponse]); // BACKEND_URL is a global constant, no dependency needed

    return { jsonFetch };
}


// --- Auth Pages ---
function LoginPage() {
    const { login } = useAuth();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate(); // For potential redirect after login if state exists
    const location = useLocation(); // To get the 'from' location

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsLoading(true);
        try {
            await login(email, password);
            // On successful login, AuthProvider handles navigation via redirectToDashboard
            // Optional: Check if there's a location state to redirect back to
            const from = location.state?.from?.pathname || null;
            if (from) {
                // Note: AuthProvider already navigates based on role. This might conflict.
                // It's usually better to let AuthProvider handle the post-login redirect.
                // navigate(from, { replace: true });
                console.log("Login successful, AuthProvider will redirect based on role.");
            }
        } catch (err) {
            setError(err.message || "Login failed. Please check credentials.");
            setIsLoading(false); // Only stop loading on error
        }
        // Don't set isLoading false on success, navigation takes over.
    };

    return (
        <PageWrapper>
            <AuthCard title="Sign in to your account">
                <form className="auth-form" onSubmit={handleSubmit}> {/* Ensure class exists */}
                    <div className="auth-form-inputs"> {/* Ensure class exists */}
                        <AnimatePresence>
                            {error && <ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} />}
                        </AnimatePresence>
                        <Input id="email-address" name="email" type="email" autoComplete="email" placeholder="Email address" value={email} onChange={(e) => setEmail(e.target.value)} />
                        <Input id="password" name="password" type="password" autoComplete="current-password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
                    </div>
                    <Button type="submit" isLoading={isLoading}><LogIn className="button-icon" />Sign in</Button> {/* Ensure class exists */}
                    <div className="auth-form-footer"> {/* Ensure class exists */}
                        <Link to="/register">Need an account? Register</Link>
                    </div>
                </form>
            </AuthCard>
        </PageWrapper>
    );
}

function RegisterPage() {
    const { register } = useAuth();
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [role, setRole] = useState('Receiver'); // Default role
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        // Basic frontend validation
        if (!name || !email || !password) {
            setError("Please fill in all fields.");
            return;
        }
        // Prevent registration with reserved admin email (case-insensitive)
        if (email.toLowerCase() === "admin@gmail.com") {
            setError("This email address is reserved and cannot be used for registration.");
            return;
        }
        if (password.length < 6) { // Example: Enforce minimum password length
            setError("Password must be at least 6 characters long.");
            return;
        }


        setError(null);
        setIsLoading(true);
        try {
            await register(name, email, password, role);
            // AuthProvider handles navigation on success
        } catch (err) {
            setError(err.message || "Registration failed. Please try again.");
            setIsLoading(false); // Stop loading only on error
        }
    };

    return (
        <PageWrapper>
            <AuthCard title="Create your account">
                <form className="auth-form" onSubmit={handleSubmit}> {/* Ensure class exists */}
                    <div className="auth-form-inputs"> {/* Ensure class exists */}
                        <AnimatePresence>
                            {error && <ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} />}
                        </AnimatePresence>
                        <Input id="name" name="name" type="text" placeholder="Full Name" value={name} onChange={(e) => setName(e.target.value)} />
                        <Input id="email-address" name="email" type="email" autoComplete="email" placeholder="Email address" value={email} onChange={(e) => setEmail(e.target.value)} />
                        <Input id="password" name="password" type="password" autoComplete="new-password" placeholder="Password (min. 6 characters)" value={password} onChange={(e) => setPassword(e.target.value)} />
                        <Select id="role" name="role" value={role} onChange={(e) => setRole(e.target.value)}>
                            <option value="Receiver">I am a Receiver</option>
                            <option value="Donor">I am a Donor</option>
                        </Select>
                    </div>
                    <Button type="submit" isLoading={isLoading}><UserPlus className="button-icon" />Create Account</Button> {/* Ensure class exists */}
                    <div className="auth-form-footer"> {/* Ensure class exists */}
                        <Link to="/login">Already have an account? Sign in</Link>
                    </div>
                </form>
            </AuthCard>
        </PageWrapper>
    );
}

// --- Shared UI Component: FormInput & FoodCard ---
const FormInput = React.forwardRef(({ label, id, type = 'text', placeholder, value, onChange, required = false, min, step, accept, ...props }, ref) => {
    const InputElement = type === 'textarea' ? 'textarea' : 'input';
    return (
        <div className="form-group"> {/* Ensure class exists */}
            <label htmlFor={id} className="form-label">{label}</label> {/* Ensure class exists */}
            <InputElement
                ref={ref}
                id={id}
                name={id}
                type={type}
                placeholder={placeholder}
                value={type !== 'file' ? value : undefined} // Don't control file input value
                // --- FIX: Pass onChange directly ---
                onChange={onChange}
                // --- END FIX ---
                required={required}
                min={min}
                step={step} // For number inputs
                accept={accept} // For file inputs
                className={type === 'textarea' ? "form-textarea" : "form-input"} // Ensure classes exist
                {...props}
            />
        </div>
    );
});
FormInput.displayName = 'FormInput';

function FoodCard({ listing, onDelete, onEdit, showDelete, showEdit, onClaim }) {
    const { user, role } = useAuth(); // Get current user role
    const isExpired = new Date(listing.expiryTime) < new Date();
    const isFullyClaimed = (listing.claims?.length || 0) >= listing.maxClaims;

    // Determine if the *current logged-in user* has claimed this specific listing
    const isClaimedByCurrentUser = user && role === 'Receiver' && (listing.claims || []).some(claim => claim.userId && claim.userId.toString() === user._id.toString());

    const remainingClaims = Math.max(0, listing.maxClaims - (listing.claims?.length || 0));

    // Determine if the claim button should be shown and enabled
    const showClaimButton = role === 'Receiver' && onClaim;
    const canClaim = !isExpired && !isFullyClaimed && !isClaimedByCurrentUser;

    // Image URL fallback
    const imageUrl = listing.imageUrl || 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image';

    return (
        <motion.div
            className={`food-card ${isExpired ? 'card-expired' : ''} ${isFullyClaimed && !isExpired ? 'card-fully-claimed' : ''}`} // Ensure classes exist
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            layout // Add layout prop for smooth animation if list changes
        >
            <div className="card-image-container"> {/* Ensure class exists */}
                <img src={imageUrl} alt={listing.description} className="card-image" onError={(e) => e.target.src = 'https://placehold.co/600x400/a7a7a7/FFF?text=Image+Error'} /> {/* Ensure class exists, added onError */}
                {(isExpired || isFullyClaimed) && (
                    <div className="card-status-overlay">{isExpired ? 'EXPIRED' : 'FULLY CLAIMED'}</div> // Ensure class exists
                )}
            </div>
            <div className="card-content"> {/* Ensure class exists */}
                <h3 className="card-title">{listing.description}</h3> {/* Ensure class exists */}
                <div className="card-details"> {/* Ensure class exists */}
                    <p><Package className="detail-icon" /> Quantity: <strong>{listing.quantity}</strong></p>
                    <p><MapPin className="detail-icon" /> Location: <strong>{listing.location}</strong></p>
                    <p><CalendarDays className="detail-icon" /> Expiry: <strong>{new Date(listing.expiryTime).toLocaleString()}</strong></p>
                    <p><Users2 className="detail-icon" /> Slots: <strong>{remainingClaims} of {listing.maxClaims} remaining</strong></p>

                    {/* Show Claimed status only if the current user is a Receiver and has claimed it */}
                    {isClaimedByCurrentUser && (
                        <p className="claimed-status"><CheckCircle className="detail-icon" /> Claimed by you!</p> // Ensure class exists
                    )}

                    {/* Show list of claimants only to Donors viewing their own card OR Admins */}
                    {(role === 'Donor' || role === 'Admin') && (showDelete || showEdit) && (
                        <div className="card-claims-list"> {/* Ensure class exists */}
                            <p style={{ marginTop: '0.5rem', fontWeight: 'bold' }}>Claims ({listing.claims?.length || 0}):</p>
                            <ul>
                                {(listing.claims && listing.claims.length > 0) ? (
                                    listing.claims.map((claim, index) => (
                                        <li key={claim.userId || index}>{claim.name || 'Unknown Claimant'}</li> // Use userId as key if available
                                    ))
                                ) : (
                                    <li>No claims yet.</li>
                                )}
                            </ul>
                        </div>
                    )}
                </div>
            </div>
            <div className="card-actions"> {/* Ensure class exists */}
                {/* Claim Button Logic */}
                {showClaimButton && (
                    <Button
                        onClick={onClaim}
                        disabled={!canClaim}
                        className="button-claim" // Ensure class exists
                    >
                        {isClaimedByCurrentUser ? 'Already Claimed' : (isFullyClaimed ? 'Fully Claimed' : (isExpired ? 'Expired' : 'Claim Food'))}
                    </Button>
                )}
                {/* Edit Button */}
                {(showEdit && onEdit) && (
                    <Button onClick={onEdit} className="button-secondary button-edit-delete" title="Edit Listing"><Edit3 /></Button> // Ensure class exists
                )}
                {/* Delete Button */}
                {(showDelete && onDelete) && (
                    <Button onClick={onDelete} className="button-danger button-edit-delete" title="Delete Listing"><Trash2 /></Button> // Ensure class exists
                )}
            </div>
        </motion.div>
    );
}


// --- Donor Dashboard Components ---

// *** UPDATED AddFoodListingForm ***
function AddFoodListingForm({ onListingCreated }) {
    const [description, setDescription] = useState('');
    const [quantity, setQuantity] = useState('');
    const [location, setLocation] = useState('');
    const [mfgTime, setMfgTime] = useState('');
    const [expiryTime, setExpiryTime] = useState('');
    const [maxClaims, setMaxClaims] = useState(1);
    const imageRef = useRef(null); // Ref to clear the file input

    // --- State for direct Cloudinary upload ---
    const [imageUrl, setImageUrl] = useState(''); // Store Cloudinary URL
    const [imagePublicId, setImagePublicId] = useState(''); // Store Cloudinary Public ID
    const [isUploadingImage, setIsUploadingImage] = useState(false);

    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);
    const [isLoading, setIsLoading] = useState(false); // Loading state for BACKEND submission
    const { jsonFetch } = useApi(); // Use jsonFetch now

    // --- Direct Upload Handler ---
    const handleImageChange = async (event) => {
        
        console.log("[DEBUG] handleImageChange started."); // NEW DEBUG
        
        const file = event.target.files[0];
        // Reset previous upload state immediately
        setImageUrl('');
        setImagePublicId('');
        setSuccess(null); // Clear previous success messages
        setError(null); // Clear previous error messages

        if (!file) {
            console.log("[DEBUG] handleImageChange: No file selected. Exiting."); // NEW DEBUG
            // Explicitly clear state if file is deselected
            if (imageRef.current) imageRef.current.value = null; // Clear the input visually
            return; // Exit if no file
        }

        console.log("[DEBUG] File selected:", file.name); // NEW DEBUG

        // Use the constants defined at the top of the file
        if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_UPLOAD_PRESET) {
            console.error("[DEBUG] CRITICAL: Cloudinary env vars missing!"); // NEW DEBUG
            console.error("[DEBUG] CLOUDINARY_CLOUD_NAME:", CLOUDINARY_CLOUD_NAME); // NEW DEBUG
            console.error("[DEBUG] CLOUDINARY_UPLOAD_PRESET:", CLOUDINARY_UPLOAD_PRESET); // NEW DEBUG
            setError("Image upload configuration is missing. Cannot upload image.");
            if (imageRef.current) imageRef.current.value = null; // Clear the input visually
            return; // EXIT HERE IF VARS ARE MISSING
        }

        console.log("[DEBUG] Cloudinary config check passed."); // NEW DEBUG
        setIsUploadingImage(true);

        const formData = new FormData();
        formData.append('file', file);
        formData.append('upload_preset', CLOUDINARY_UPLOAD_PRESET); // Use constant

        try {
            console.log(`[DEBUG] Uploading to Cloudinary: ${CLOUDINARY_CLOUD_NAME}`); // Use constant // NEW DEBUG
            const uploadUrl = `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/image/upload`; // Use constant
            console.log("[DEBUG] Upload URL:", uploadUrl); // NEW DEBUG
            
            const response = await fetch(uploadUrl, {
                method: 'POST',
                body: formData,
            });

            console.log("[DEBUG] Cloudinary response status:", response.status); // NEW DEBUG
            const data = await response.json(); // Always try to parse JSON
            console.log("[DEBUG] Cloudinary response data:", data); // NEW DEBUG


            if (!response.ok) {
                // Use error message from Cloudinary if available
                const errorMessage = data?.error?.message || `Cloudinary upload failed with status ${response.status}`;
                 console.error("[DEBUG] Cloudinary API error:", errorMessage); // NEW DEBUG
                throw new Error(errorMessage);
            }

            console.log("[DEBUG] Cloudinary upload successful:", data); // NEW DEBUG
            setImageUrl(data.secure_url); // Store the returned URL
            setImagePublicId(data.public_id); // Store the public_id
            setSuccess("✓ Image uploaded successfully."); // Provide user feedback

        } catch (err) {
            console.error("[DEBUG] Catch block: Cloudinary upload error:", err); // NEW DEBUG
            setError(`Image upload failed: ${err.message || 'Unknown network error'}`); // More specific error
            if (imageRef.current) imageRef.current.value = null; // Clear file input on error
        } finally {
            console.log("[DEBUG] Upload process finished. isUploadingImage set to false."); // NEW DEBUG
            setIsUploadingImage(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        console.log("[DEBUG] handleSubmit started."); // NEW DEBUG

        // --- Frontend Validations ---
        if (maxClaims < 1) { setError("Max claims must be at least 1."); return; }
        if (!mfgTime || !expiryTime) { setError("Manufacture and Expiry times are required."); return; }
        const mfgDate = new Date(mfgTime);
        const expiryDate = new Date(expiryTime);
        if (isNaN(mfgDate.getTime()) || isNaN(expiryDate.getTime())) { setError('Invalid date format.'); return; }
        if (expiryDate <= mfgDate) { setError('Expiry time must be after manufacture time.'); return; }
        
        // Check if an image was selected but hasn't finished uploading or failed
        const fileSelected = imageRef.current?.files?.length > 0;
        console.log("[DEBUG] File selected check:", fileSelected); // NEW DEBUG
        console.log("[DEBUG] imageUrl state:", imageUrl); // NEW DEBUG
        console.log("[DEBUG] isUploadingImage state:", isUploadingImage); // NEW DEBUG

        if (fileSelected && !imageUrl && !isUploadingImage) {
            console.error("[DEBUG] Submit validation failed: Image selected but no URL and not uploading."); // NEW DEBUG
            setError("Image selected but upload did not complete. Please wait or re-select/remove the image.");
            return;
        }
        console.log("[DEBUG] Submit validation passed."); // NEW DEBUG
        // --- End Validations ---

        setError(null);
        // Don't clear success message from image upload yet
        setIsLoading(true); // Backend submission loading state

        try {
            // Data to send to YOUR backend (including Cloudinary results)
            const listingData = {
                description,
                quantity,
                location,
                mfgTime, // Send as ISO string or let backend parse
                expiryTime, // Send as ISO string or let backend parse
                maxClaims: parseInt(maxClaims, 10) || 1,
                imageUrl: imageUrl || null, // Send URL or null
                imagePublicId: imagePublicId || null // Send Public ID or null
            };

            console.log("[DEBUG] Submitting to backend:", listingData); // Log data being sent

            await jsonFetch('/food', {
                method: 'POST',
                body: JSON.stringify(listingData), // Send JSON data
            });

            console.log("[DEBUG] Backend submission successful."); // NEW DEBUG
            setSuccess('Listing created successfully!'); // Set final success message
            // Reset form completely
            setDescription(''); setQuantity(''); setLocation('');
            setMfgTime(''); setExpiryTime(''); setMaxClaims(1);
            setImageUrl(''); setImagePublicId(''); // Clear image state
            if (imageRef.current) imageRef.current.value = null; // Clear file input
            // Call parent callback AFTER state reset to prevent issues
            if (onListingCreated) {
                onListingCreated(); // Callback to refresh list in parent
            }


        } catch (err) {
            console.error("[DEBUG] Backend submission error:", err); // NEW DEBUG
            // Use specific error from backend if available
            setError(err.message || "Failed to create listing. Please try again.");
            setSuccess(null); // Clear any previous success message
        } finally {
            console.log("[DEBUG] Backend submission finished. isLoading set to false."); // NEW DEBUG
            setIsLoading(false);
        }
    };

    return (
        <motion.div className="add-food-form-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <h2>Create New Listing</h2>
            <form onSubmit={handleSubmit}>
                <AnimatePresence mode="wait">
                    {/* Display error OR success, not both at the same time for final status */}
                    {error && !success && <ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} />}
                    {success && <SuccessMessage key="success-msg" message={success} onDismiss={() => setSuccess(null)} />}
                </AnimatePresence>

                <FormInput label="Description" id="description" type="text" placeholder="e.g., 10 vegetable curry meals" value={description} onChange={(e) => setDescription(e.target.value)} required={true} />
                <div className="form-group-grid">
                    <FormInput label="Quantity" id="quantity" type="text" placeholder="e.g., 10 packets, 5 kg" value={quantity} onChange={(e) => setQuantity(e.target.value)} required={true} />
                    <FormInput label="Maximum Claims" id="maxClaims" type="number" min="1" placeholder="1" value={maxClaims} onChange={(e) => setMaxClaims(Number(e.target.value) || 1)} required={true} />
                </div>
                <FormInput label="Pickup Location" id="location" type="text" placeholder="Full address" value={location} onChange={(e) => setLocation(e.target.value)} required={true} />

                {/* --- Updated File Input --- */}
                <FormInput
                    label="Image File (Optional)"
                    id="image"
                    type="file"
                    ref={imageRef} // Use ref to clear the input
                    onChange={handleImageChange} // Use the direct upload handler
                    accept="image/*" // Specify acceptable file types
                    required={false}
                    disabled={isUploadingImage} // Disable while uploading to Cloudinary
                />
                {isUploadingImage && <p style={{ marginTop: '-0.5rem', marginBottom: '1rem', fontSize: '0.9em' }}><Loader2 className="spinner-inline" /> Uploading image...</p>}
                {/* Display thumbnail or link after successful Cloudinary upload */}
                {imageUrl && !isUploadingImage && (
                    <div style={{ marginTop: '-0.5rem', marginBottom: '1rem', fontSize: '0.9em', display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <img src={imageUrl} alt="Upload Preview" style={{ maxWidth: '80px', maxHeight: '80px', objectFit: 'cover', borderRadius: '4px' }} />
                        {/* Optionally add a remove button here if needed before submit */}
                    </div>
                )}
                {/* --- End Updated File Input --- */}


                <div className="form-group-grid">
                    <FormInput label="Manufacture Time" id="mfgTime" type="datetime-local" value={mfgTime} onChange={(e) => setMfgTime(e.target.value)} required={true} />
                    <FormInput label="Expiry Time" id="expiryTime" type="datetime-local" value={expiryTime} onChange={(e) => setExpiryTime(e.target.value)} required={true} />
                </div>
                <div style={{ marginTop: '1.5rem' }}>
                    {/* Disable submit while EITHER Cloudinary upload OR backend submit is happening */}
                    <Button type="submit" isLoading={isLoading || isUploadingImage} disabled={isUploadingImage}>
                        <PlusCircle className="button-icon" />Add Listing
                    </Button>
                </div>
            </form>
        </motion.div>
    );
}

// *** UPDATED EditFoodListingForm ***
function EditFoodListingForm({ listing, onListingUpdated, onCancel }) {
    const formatDate = (d) => {
        try {
            if (!d) return '';
            const date = new Date(d);
            // Check if date is valid
            if (isNaN(date.getTime())) return '';
            // Adjust for timezone offset before slicing
            const timezoneOffset = date.getTimezoneOffset() * 60000; // Offset in milliseconds
            const localISOTime = new Date(date.getTime() - timezoneOffset).toISOString().slice(0, 16);
            return localISOTime;
        } catch (e) {
            console.error("Error formatting date:", d, e);
            return '';
        }
    };

    const [description, setDescription] = useState(listing.description);
    const [quantity, setQuantity] = useState(listing.quantity);
    const [location, setLocation] = useState(listing.location);
    const [mfgTime, setMfgTime] = useState(formatDate(listing.mfgTime));
    const [expiryTime, setExpiryTime] = useState(formatDate(listing.expiryTime));
    const [maxClaims, setMaxClaims] = useState(listing.maxClaims);
    const imageRef = useRef(null); // Ref to clear file input

    // --- State for direct Cloudinary upload ---
    const [imageUrl, setImageUrl] = useState(listing.imageUrl || ''); // Initialize with current URL
    const [imagePublicId, setImagePublicId] = useState(listing.imagePublicId || ''); // Initialize with current public ID
    const [isUploadingImage, setIsUploadingImage] = useState(false);
    const [imageChanged, setImageChanged] = useState(false); // Track if file input was interacted with

    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);
    const [isLoading, setIsLoading] = useState(false); // Loading for backend submission
    const { jsonFetch } = useApi(); // Use jsonFetch

    // --- Direct Upload Handler (Identical to Add Form, but logging context) ---
    const handleImageChange = async (event) => {
        console.log("[DEBUG] EditForm: handleImageChange started."); // NEW DEBUG
        
        const file = event.target.files[0];
        setImageChanged(true); // Mark interaction
        // Reset previous upload state on new selection
        setSuccess(null);
        setError(null);


        if (!file) {
            console.log("[DEBUG] EditForm: No file selected or file removed."); // NEW DEBUG
            // Don't clear imageUrl/Id yet, let handleRemoveImage do that explicitly
            return;
        }
        
        console.log("[DEBUG] EditForm: File selected:", file.name); // NEW DEBUG


        // Use the constants defined at the top of the file
        if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_UPLOAD_PRESET) {
            console.error("[DEBUG] EditForm: CRITICAL: Cloudinary env vars missing!"); // NEW DEBUG
            setError("Image upload configuration is missing.");
            if (imageRef.current) imageRef.current.value = null; // Clear visually
            setImageChanged(false); // Reset interaction marker
            return; // EXIT HERE IF VARS ARE MISSING
        }

        console.log("[DEBUG] EditForm: Cloudinary config check passed."); // NEW DEBUG
        setIsUploadingImage(true);

        const formData = new FormData();
        formData.append('file', file);
        formData.append('upload_preset', CLOUDINARY_UPLOAD_PRESET); // Use constant
        // Optional: If you want Cloudinary to replace the image using the existing public_id
        // if (imagePublicId) formData.append('public_id', imagePublicId);

        try {
            console.log(`[DEBUG] EditForm: Uploading update to Cloudinary: ${CLOUDINARY_CLOUD_NAME}`); // NEW DEBUG
             const uploadUrl = `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/image/upload`; // Use constant
             console.log("[DEBUG] EditForm: Upload URL:", uploadUrl); // NEW DEBUG

            const response = await fetch(uploadUrl, {
                method: 'POST',
                body: formData,
            });
            console.log("[DEBUG] EditForm: Cloudinary response status:", response.status); // NEW DEBUG
            const data = await response.json();
             console.log("[DEBUG] EditForm: Cloudinary response data:", data); // NEW DEBUG
            if (!response.ok) {
                 const errorMessage = data?.error?.message || `Cloudinary upload failed with status ${response.status}`;
                 console.error("[DEBUG] EditForm: Cloudinary API error:", errorMessage); // NEW DEBUG
                throw new Error(errorMessage);
            }
            console.log("[DEBUG] EditForm: Cloudinary upload successful:", data); // NEW DEBUG
            setImageUrl(data.secure_url); // Store the NEW URL
            setImagePublicId(data.public_id); // Store the NEW Public ID
            setSuccess("✓ New image uploaded successfully.");

        } catch (err) {
            console.error("[DEBUG] EditForm: Catch block: Cloudinary upload error:", err); // NEW DEBUG
            setError(`New image upload failed: ${err.message || 'Unknown network error'}`); // More specific
            if (imageRef.current) imageRef.current.value = null; // Clear file input
            setImageChanged(false); // Reset interaction marker
            // Revert to original image state on upload failure? Or keep empty?
            // setImageUrl(listing.imageUrl || ''); // Revert to original
            // setImagePublicId(listing.imagePublicId || '');
        } finally {
            console.log("[DEBUG] EditForm: Upload process finished. isUploadingImage set to false."); // NEW DEBUG
            setIsUploadingImage(false);
        }
    };

    // --- Handle Image Removal ---
    const handleRemoveImage = () => {
        if (window.confirm("Are you sure you want to remove the current image? The change will be saved when you update the listing.")) {
            console.log("[DEBUG] Removing image."); // NEW DEBUG
            setImageUrl('');
            setImagePublicId('');
            if (imageRef.current) imageRef.current.value = null; // Clear file input
            setImageChanged(true); // Mark interaction
            setSuccess("Image marked for removal."); // Inform user
        }
    };


    const handleSubmit = async (e) => {
        e.preventDefault();
        console.log("[DEBUG] EditForm: handleSubmit started."); // NEW DEBUG

        // --- Frontend Validations ---
        if (maxClaims < 1) { setError("Max claims must be at least 1."); return; }
        if (!mfgTime || !expiryTime) { setError("Manufacture and Expiry times are required."); return; }
        const mfgDate = new Date(mfgTime);
        const expiryDate = new Date(expiryTime);
        if (isNaN(mfgDate.getTime()) || isNaN(expiryDate.getTime())) { setError('Invalid date format.'); return; }
        if (expiryDate <= mfgDate) { setError('Expiry time must be after manufacture time.'); return; }
        
        // Check if a new image was selected but hasn't finished uploading or failed
        const fileSelected = imageRef.current?.files?.length > 0;
        console.log("[DEBUG] EditForm: File selected check:", fileSelected); // NEW DEBUG
        console.log("[DEBUG] EditForm: imageChanged state:", imageChanged); // NEW DEBUG
        console.log("[DEBUG] EditForm: imageUrl state:", imageUrl); // NEW DEBUG
        console.log("[DEBUG] EditForm: isUploadingImage state:", isUploadingImage); // NEW DEBUG

        if (imageChanged && fileSelected && !imageUrl && !isUploadingImage) {
            console.error("[DEBUG] EditForm: Submit validation failed: New image selected but no URL and not uploading."); // NEW DEBUG
            setError("New image selected but upload did not complete. Please wait or re-select/remove.");
            return;
        }
        console.log("[DEBUG] EditForm: Submit validation passed."); // NEW DEBUG
        // --- End Validations ---

        setError(null);
        // Keep image status message if relevant, backend success will override
        setIsLoading(true);

        try {
            // Data to send to YOUR backend
            const listingData = {
                description,
                quantity,
                location,
                mfgTime,
                expiryTime,
                maxClaims: parseInt(maxClaims, 10) || 1,
                // Send current imageUrl/Id state (could be new, old, or null if removed)
                imageUrl: imageUrl || null,
                imagePublicId: imagePublicId || null,
            };

            console.log("[DEBUG] EditForm: Submitting Update to backend:", listingData); // NEW DEBUG

            // Use PUT request for update
            const updated = await jsonFetch(`/food/${listing._id}`, {
                method: 'PUT',
                body: JSON.stringify(listingData), // Send JSON
            });
            console.log("[DEBUG] EditForm: Backend update successful."); // NEW DEBUG
            setSuccess('Listing updated successfully!'); // Set final success
            setImageChanged(false); // Reset image changed flag after successful save
            // Call parent callback AFTER state reset/success message
            if (onListingUpdated) {
                onListingUpdated(updated); // Callback to refresh list and close modal/form
            }


        } catch (err) {
            console.error("[DEBUG] EditForm: Backend update error:", err); // NEW DEBUG
            setError(err.message || "Failed to update listing. Please try again.");
            setSuccess(null); // Clear any previous success message
        } finally {
            console.log("[DEBUG] EditForm: Backend submission finished. isLoading set to false."); // NEW DEBUG
            setIsLoading(false);
        }
    };

    return (
        <motion.div className="add-food-form-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <h2>Edit Listing: {listing.description}</h2>
            <form onSubmit={handleSubmit}>
                <AnimatePresence mode="wait">
                    {/* Display error OR success */}
                    {error && !success && <ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} />}
                    {success && <SuccessMessage key="success-msg" message={success} onDismiss={() => setSuccess(null)} />}
                </AnimatePresence>

                {/* --- Form Inputs --- */}
                <FormInput label="Description" id="description-edit" type="text" value={description} onChange={(e) => setDescription(e.target.value)} required={true} />
                <div className="form-group-grid">
                    <FormInput label="Quantity" id="quantity-edit" type="text" value={quantity} onChange={(e) => setQuantity(e.target.value)} required={true} />
                    <FormInput label="Maximum Claims" id="maxClaims-edit" type="number" min="1" value={maxClaims} onChange={(e) => setMaxClaims(Number(e.target.value) || 1)} required={true} />
                </div>
                <FormInput label="Pickup Location" id="location-edit" type="text" value={location} onChange={(e) => setLocation(e.target.value)} required={true} />

                {/* --- Updated File Input & Preview/Remove --- */}
                <FormInput
                    label="Image (Select file to replace, or Remove below)"
                    id="image-edit"
                    type="file"
                    ref={imageRef}
                    onChange={handleImageChange} // Use direct upload handler
                    accept="image/*" // Specify types
                    required={false}
                    disabled={isUploadingImage}
                />
                {isUploadingImage && <p style={{ marginTop: '-0.5rem', marginBottom: '1rem', fontSize: '0.9em' }}><Loader2 className="spinner-inline" /> Uploading new image...</p>}

                {/* Show current/new image preview OR 'No Image' text */}
                {!isUploadingImage && imageUrl && (
                    <div style={{ marginTop: '-0.5rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <img src={imageUrl} alt="Current/Preview" style={{ maxWidth: '80px', maxHeight: '80px', objectFit: 'cover', borderRadius: '4px' }} />
                        <Button type="button" onClick={handleRemoveImage} className="button-icon-only button-danger button-small" title="Mark Image for Removal">
                            <ImageOff size={16} />
                        </Button>
                    </div>
                )}
                {!isUploadingImage && !imageUrl && (
                    <p style={{ marginTop: '-0.5rem', marginBottom: '1rem', fontSize: '0.9em', color: '#888' }}>(No image)</p>
                )}
                {/* --- End Updated File Input --- */}


                <div className="form-group-grid">
                    <FormInput label="Manufacture Time" id="mfgTime-edit" type="datetime-local" value={mfgTime} onChange={(e) => setMfgTime(e.target.value)} required={true} />
                    <FormInput label="Expiry Time" id="expiryTime-edit" type="datetime-local" value={expiryTime} onChange={(e) => setExpiryTime(e.target.value)} required={true} />
                </div>
                {/* --- End Form Inputs --- */}

                <div style={{ marginTop: '1.5rem', display: 'flex', gap: 'rem' }}>
                    <Button type="submit" isLoading={isLoading || isUploadingImage} disabled={isUploadingImage} className="button-primary">
                        <Edit3 className="button-icon" />Update Listing
                    </Button>
                    <Button type="button" onClick={onCancel} className="button-secondary" disabled={isLoading || isUploadingImage}>
                        Cancel
                    </Button>
                </div>
            </form>
        </motion.div>
    );
}

// --- Donor Dashboard (No structural changes needed, uses updated forms) ---
function DonorDashboard() {
    const [view, setView] = useState('view'); // 'view', 'add', 'edit'
    const [listingToEdit, setListingToEdit] = useState(null);
    const [myListings, setMyListings] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [successMessage, setSuccessMessage] = useState(null);
    const { jsonFetch } = useApi();

    // Fetch donor's listings
    const fetchMyListings = useCallback(async () => {
        setIsLoading(true);
        setError(null);
        // setSuccessMessage(null); // Keep success message until dismissed or new action
        try {
            console.log("Fetching donor listings...");
            const data = await jsonFetch('/food/donor/me');
            console.log("Donor listings received:", data);
            setMyListings(data || []); // Ensure it's an array
        } catch (err) {
            console.error("Error fetching donor listings:", err);
            setError(err.message || "Failed to fetch listings.");
            setMyListings([]); // Clear listings on error
        } finally {
            setIsLoading(false);
        }
    }, [jsonFetch]);

    // Handle creation/update completion
    const handleListingCreatedOrUpdated = useCallback(() => {
        setView('view');
        setListingToEdit(null);
        fetchMyListings(); // Refresh the list
    }, [fetchMyListings]); // Add fetchMyListings dependency

    // Handle delete action
    const handleDeleteListing = async (listingId) => {
        if (!window.confirm("Are you sure you want to delete this listing? This action cannot be undone.")) return;
        setError(null);
        setSuccessMessage(null);
        // Consider setting a specific loading state for delete if needed
        try {
            console.log(`Deleting listing: ${listingId}`);
            await jsonFetch(`/food/${listingId}`, { method: 'DELETE' });
            setSuccessMessage('Listing deleted successfully!');
            // Optimistic UI update or fetch again
            // setMyListings(prev => prev.filter(l => l._id !== listingId));
            fetchMyListings(); // Fetch again for consistency
        } catch (err) {
            console.error("Error deleting listing:", err);
            setError(err.message || "Failed to delete listing.");
        } finally {
            // Turn off delete loading state if used
        }
    };

    // Fetch listings on component mount
    useEffect(() => {
        fetchMyListings();
    }, [fetchMyListings]);

    // Render logic based on view state
    const renderContent = () => {
        if (view === 'add') {
            return (
                <AddFoodListingForm
                    onListingCreated={() => {
                        setSuccessMessage('Listing created successfully!'); // Set success message
                        handleListingCreatedOrUpdated();
                    }}
                />
            );
        }
        if (view === 'edit' && listingToEdit) {
            return (
                <EditFoodListingForm
                    listing={listingToEdit}
                    onListingUpdated={(updatedListing) => { // updatedListing might be passed back
                        setSuccessMessage('Listing updated successfully!'); // Set success message
                        // Optionally update local state immediately if needed, otherwise rely on fetch
                        setMyListings(currentListings =>
                            currentListings.map(l => (l._id === updatedListing._id ? updatedListing : l))
                        );
                        handleListingCreatedOrUpdated(); // Switches view and refetches
                    }}
                    onCancel={() => { setView('view'); setListingToEdit(null); }}
                />
            );
        }

        // Default 'view' state
        if (isLoading && myListings.length === 0) return <LoadingSpinner />; // Show spinner only on initial load

        return (
            <>
                <div className="dashboard-actions"> {/* Ensure class exists */}
                    <Button onClick={() => { setView('add'); setSuccessMessage(null); setError(null); }} className="button-success">
                        <PlusCircle className="button-icon" /> Add New Listing
                    </Button>
                </div>
                <AnimatePresence mode="wait">
                    {/* Show error OR success */}
                    {error && <ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} />}
                    {successMessage && <SuccessMessage key="success-msg" message={successMessage} onDismiss={() => setSuccessMessage(null)} />}
                </AnimatePresence>
                <h2 className="dashboard-title">My Listings</h2> {/* Ensure class exists */}
                {myListings.length === 0 && !isLoading ? (
                    <div className="empty-state"> {/* Ensure class exists */}
                        <Package />
                        <p>You haven't created any listings yet. Click "Add New Listing" to start sharing!</p>
                    </div>
                ) : (
                    <div className="food-list-grid"> {/* Ensure class exists */}
                        <AnimatePresence>
                            {myListings.map(listing => (
                                <FoodCard
                                    key={listing._id}
                                    listing={listing}
                                    showDelete={true}
                                    showEdit={true}
                                    onDelete={() => handleDeleteListing(listing._id)}
                                    onEdit={() => {
                                        setListingToEdit(listing);
                                        setView('edit');
                                        setSuccessMessage(null); // Clear messages when switching view
                                        setError(null);
                                    }}
                                />
                            ))}
                        </AnimatePresence>
                    </div>
                )}
            </>
        );
    };

    return (
        <PageWrapper>
            <h1 className="page-header"><HeartHandshake className="header-icon" /> Donor Dashboard</h1> {/* Ensure classes exist */}
            <div className="dashboard-container">{renderContent()}</div> {/* Ensure class exists */}
        </PageWrapper>
    );
}


// --- Receiver Dashboard ---
function ReceiverDashboard() {
    const { user } = useAuth(); // Get user to potentially filter out own claims if needed? (Backend handles donor exclusion)
    const [allListings, setAllListings] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [successMessage, setSuccessMessage] = useState(null);
    const [claimingId, setClaimingId] = useState(null); // Track which listing is being claimed
    const { jsonFetch } = useApi();

    // Fetch all available listings
    const fetchAllListings = useCallback(async () => {
        setIsLoading(true);
        setError(null);
        // setSuccessMessage(null); // Keep success message
        try {
            console.log("Fetching available listings...");
            const data = await jsonFetch('/food'); // Backend filters expired/full
            console.log("Available listings received:", data);
            // Ensure data is always an array
            const available = Array.isArray(data) ? data : [];
            // Filter out listings where the current receiver has already claimed a slot
            // Keep this logic, but maybe show them differently later?
            const filteredForUserClaims = user
                ? available.filter(l => !(l.claims || []).some(c => c.userId && c.userId.toString() === user._id.toString()))
                : available; // Show all if user not loaded? Or handle differently?
            
            // Reverting the filter for now - show all, FoodCard handles display
            // setAllListings(filteredForUserClaims); 
            setAllListings(available);

        } catch (err) {
            console.error("Error fetching available listings:", err);
            setError(err.message || "Failed to fetch listings.");
            setAllListings([]);
        } finally {
            setIsLoading(false);
        }
    }, [jsonFetch, user]); // Depend on user

    // Handle claim action
    const handleClaimFood = async (listingId) => {
        setError(null);
        setSuccessMessage(null);
        setClaimingId(listingId); // Set loading state for the specific button

        // Find the listing locally to perform checks (optional, backend validates too)
        const listing = allListings.find(l => l._id === listingId);
        if (!user) { setError("You must be logged in to claim."); setClaimingId(null); return; }
        if (!listing) { setError("Listing not found."); setClaimingId(null); return; } // Should not happen
        if ((listing.claims || []).some(c => c.userId && c.userId.toString() === user._id.toString())) { setError("You have already claimed this."); setClaimingId(null); return; }
        if ((listing.claims || []).length >= listing.maxClaims) { setError("This listing is now fully claimed."); setClaimingId(null); return; }
        if (new Date(listing.expiryTime) < new Date()) { setError("This listing has expired."); setClaimingId(null); return; }

        try {
            console.log(`Claiming listing: ${listingId}`);
            const updatedListing = await jsonFetch(`/food/${listingId}/claim`, { method: 'POST' });
            console.log("Claim successful, updated listing:", updatedListing);
            setSuccessMessage(`Claimed '${updatedListing.description}'! Please contact the donor to arrange pickup.`);

            // Update the specific listing in the state to reflect the claim immediately
            setAllListings(prevListings =>
                prevListings.map(l => (l._id === listingId ? updatedListing : l))
            );

        } catch (err) {
            console.error("Error claiming listing:", err);
            setError(err.message || "Failed to claim listing.");
            // Optional: Refetch listings on error to get latest status
            fetchAllListings();
        } finally {
            setClaimingId(null); // Reset loading state for the button
        }
    };

    // Fetch listings on mount
    useEffect(() => {
        fetchAllListings();
    }, [fetchAllListings]);

    // Initial loading state
    if (isLoading && allListings.length === 0) return <LoadingSpinner />;

    return (
        <PageWrapper>
            <h1 className="page-header"><List className="header-icon" /> Available Food Listings</h1> {/* Ensure classes exist */}
            <div className="dashboard-container"> {/* Ensure class exists */}
                <AnimatePresence mode="wait">
                    {error && <ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} />}
                    {successMessage && <SuccessMessage key="success-msg" message={successMessage} onDismiss={() => setSuccessMessage(null)} />}
                </AnimatePresence>
                <p className="page-intro">Browse available donations. Click "Claim Food" to reserve a slot and arrange pickup with the donor.</p> {/* Ensure class exists */}

                {(allListings.length === 0 && !isLoading) ? (
                    <div className="empty-state"> {/* Ensure class exists */}
                        <Package />
                        <p>No active listings available right now. Check back soon!</p>
                    </div>
                ) : (
                    <div className="food-list-grid"> {/* Ensure class exists */}
                        <AnimatePresence>
                            {allListings.map(listing => (
                                <FoodCard
                                    key={listing._id}
                                    listing={listing}
                                    onClaim={() => handleClaimFood(listing._id)}
                                // Pass loading state specific to this card's claim button
                                // You might need to adjust FoodCard to accept an 'isClaiming' prop
                                // Or adjust the Button component inside FoodCard if `onClaim` is the only action
                                />
                            ))}
                        </AnimatePresence>
                    </div>
                )}
                {/* Show loading indicator if fetching updates */}
                {isLoading && <LoadingSpinner />}
            </div>
        </PageWrapper>
    );
}

// --- Admin Dashboard Components ---

function StatCard({ title, value, icon, className }) {
    return (
        <motion.div className={`stat-card ${className}`} whileHover={{ scale: 1.02 }}> {/* Ensure classes exist */}
            <div className="stat-icon-container">{icon}</div> {/* Ensure class exists */}
            <div className="stat-content"> {/* Ensure class exists */}
                <p className="stat-value">{value}</p> {/* Ensure class exists */}
                <h3 className="stat-title">{title}</h3> {/* Ensure class exists */}
            </div>
        </motion.div>
    );
}

// PDF Generation Function (Needs jsPDF, jspdf-autotable installed)
const generatePDF = (listings) => {
    if (!listings || listings.length === 0) {
        alert("No data available to generate PDF for the current filter.");
        return;
    }

    const doc = new jsPDF();
    const tableColumn = ["Description", "Donor", "Status", "Expires", "Claims", "Created At"];
    const tableRows = [];

    // Title
    doc.setFontSize(18);
    doc.text("Food Listings Report", 14, 22);

    // Prepare data
    listings.forEach(listing => {
        const isExpired = new Date(listing.expiryTime) < new Date();
        const isFullyClaimed = (listing.claims?.length || 0) >= listing.maxClaims;
        const status = isExpired ? "Expired" : (isFullyClaimed ? "Fully Claimed" : "Active");

        const listingData = [
            listing.description,
            listing.donorName || 'N/A',
            status,
            new Date(listing.expiryTime).toLocaleString(),
            `${listing.claims?.length || 0}/${listing.maxClaims}`,
            new Date(listing.createdAt).toLocaleDateString() // Add creation date
        ];
        tableRows.push(listingData);
    });

    // Add table using autoTable
    doc.autoTable({
        head: [tableColumn],
        body: tableRows,
        startY: 30, // Start table below the title
        theme: 'grid', // or 'striped' or 'plain'
        styles: { fontSize: 8, cellPadding: 2, overflow: 'linebreak' },
        headStyles: { fillColor: [79, 70, 229], textColor: 255 }, // Header color (primary), white text
        columnStyles: { // Adjust column widths if needed
            0: { cellWidth: 40 }, // Description
            1: { cellWidth: 30 }, // Donor
            2: { cellWidth: 20 }, // Status
            3: { cellWidth: 35 }, // Expires
            4: { cellWidth: 20 }, // Claims
            5: { cellWidth: 25 }, // Created At
        }
    });

    // Add date generated
    const date = new Date().toLocaleDateString();
    const time = new Date().toLocaleTimeString();
    doc.setFontSize(10);
    doc.text(`Generated on: ${date} ${time}`, 14, doc.lastAutoTable.finalY + 10);

    // Save the PDF
    const filename = `food_listings_report_${date.replace(/\//g, '-')}.pdf`;
    doc.save(filename);
};

// Admin Table for Listings
function ListingListTable({ listings, onDelete }) {
    return (
        <div className="admin-table-card"> {/* Ensure class exists */}
            {/* Title and Download Button */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1.5rem 1.5rem 1rem 1.5rem', borderBottom: '1px solid #e5e7eb' }}>
                <h3>Food Listings</h3>
                <Button
                    onClick={() => generatePDF(listings)} // Call PDF generation function
                    className="button-secondary button-small" // Ensure classes exist
                    disabled={listings.length === 0}
                    title="Download current list as PDF"
                >
                    <Download size={16} style={{ marginRight: '4px' }} /> PDF
                </Button>
            </div>
            <div className="table-wrapper"> {/* Ensure class exists */}
                <table className="data-table"> {/* Ensure class exists */}
                    <thead>
                        <tr>
                            <th>Description</th>
                            <th>Donor</th>
                            <th>Status</th>
                            <th>Expires</th>
                            <th>Claims</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {listings.map(listing => {
                            const isExpired = new Date(listing.expiryTime) < new Date();
                            const isFullyClaimed = (listing.claims?.length || 0) >= listing.maxClaims;
                            const status = isExpired ? "Expired" : (isFullyClaimed ? "Fully Claimed" : "Active");
                            return (
                                <tr key={listing._id} className={isExpired ? 'expired-row' : ''}> {/* Ensure class exists */}
                                    <td>{listing.description}</td>
                                    <td>{listing.donorName || 'N/A'}</td>
                                    <td>
                                        {/* Ensure status tag classes exist */}
                                        <span className={`status-tag status-${status.toLowerCase().replace(' ', '-')}`}>
                                            {status}
                                        </span>
                                    </td>
                                    <td>{new Date(listing.expiryTime).toLocaleString()}</td>
                                    <td>{listing.claims?.length || 0}/{listing.maxClaims}</td>
                                    <td>{new Date(listing.createdAt).toLocaleDateString()}</td>
                                    <td>
                                        <Button onClick={() => onDelete(listing._id)} className="button-icon-only button-danger" title="Delete Listing"> {/* Ensure classes exist */}
                                            <Trash2 />
                                        </Button>
                                    </td>
                                </tr>
                            );
                        })}
                        {listings.length === 0 && <tr><td colSpan="7" style={{ textAlign: 'center', padding: '2rem' }}>No listings found for the selected filter.</td></tr>}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// Admin Dashboard Component
function AdminDashboard() {
    // State for stats, listings, loading, error, success, filter
    const [stats, setStats] = useState({ totalUsers: 0, totalDonors: 0, totalListings: 0, activeListings: 0 });
    const [listings, setListings] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [successMessage, setSuccessMessage] = useState(null);
    const [filter, setFilter] = useState(''); // State for filter dropdown ('', '1week', '1month', '1year')
    const { jsonFetch } = useApi();

    // Fetch dashboard data (stats and filtered listings)
    const fetchData = useCallback(async () => {
        setIsLoading(true);
        setError(null);
        // setSuccessMessage(null); // Keep success message until dismissed or new action
        const filterQuery = filter ? `?filter=${filter}` : '';
        console.log(`Fetching admin data with filter: ${filter || 'None'}`);

        try {
            // Fetch stats and listings in parallel
            const [statsData, listingsData] = await Promise.all([
                jsonFetch(`/admin/dashboard${filterQuery}`), // Stats endpoint might use filter for counts
                jsonFetch(`/admin/food${filterQuery}`)      // Listings endpoint uses filter
            ]);

            console.log("Admin Stats:", statsData);
            console.log("Admin Listings:", listingsData);

            setStats(statsData || { totalUsers: 0, totalDonors: 0, totalListings: 0, activeListings: 0 }); // Provide default structure
            setListings(Array.isArray(listingsData) ? listingsData : []); // Ensure listings is always an array

        } catch (err) {
            console.error("Error fetching admin data:", err);
            setError(err.message || "Failed to load admin dashboard data.");
            setStats({ totalUsers: 0, totalDonors: 0, totalListings: 0, activeListings: 0 }); // Reset stats on error
            setListings([]); // Reset listings on error
        } finally {
            setIsLoading(false);
        }
    }, [jsonFetch, filter]); // Re-fetch when filter changes

    // Delete listing function for Admin
    const handleDeleteListing = async (listingId) => {
        if (!window.confirm("ADMIN ACTION: Are you sure you want to permanently delete this listing?")) return;
        setError(null); setSuccessMessage(null);
        // Optional: Set a specific loading state for deletion
        try {
            console.log(`Admin deleting listing: ${listingId}`);
            await jsonFetch(`/admin/food/${listingId}`, { method: 'DELETE' });
            setSuccessMessage('Listing deleted successfully by Admin.');
            // Optimistic UI update or refetch
            // setListings(prev => prev.filter(l => l._id !== listingId));
            fetchData(); // Refetch data to ensure consistency after delete
        } catch (err) {
            console.error("Error deleting listing (Admin):", err);
            setError(err.message || "Failed to delete listing.");
        } finally {
            // Turn off specific loading state if used
        }
    };

    // Fetch data on initial load and whenever the filter state changes
    useEffect(() => {
        fetchData();
    }, [fetchData]); // fetchData includes filter as a dependency

    // Display loading spinner only on initial full load
    if (isLoading && listings.length === 0 && !error) return <LoadingSpinner />;

    return (
        <PageWrapper>
            <h1 className="page-header"><LayoutDashboard className="header-icon" /> Admin Dashboard</h1> {/* Ensure classes exist */}
            <div className="dashboard-container admin-dashboard"> {/* Ensure classes exist */}
                <AnimatePresence mode="wait">
                    {error && <ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} />}
                    {successMessage && <SuccessMessage key="success-msg" message={successMessage} onDismiss={() => setSuccessMessage(null)} />}
                </AnimatePresence>

                {/* Filter UI */}
                <div className="admin-filter-bar"> {/* Ensure class exists */}
                    <label htmlFor="admin-filter" className="form-label">Filter Listings By Creation Date:</label>
                    <select
                        id="admin-filter"
                        className="form-select" // Ensure class exists
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)} // Update filter state on change
                        style={{ maxWidth: '250px' }}
                    >
                        <option value="">All Time</option>
                        <option value="1week">Last 7 Days</option>
                        <option value="1month">Last 30 Days</option>
                        {/* <option value="3month">Last 3 Months</option> */} {/* Add backend support if needed */}
                        <option value="1year">Last 1 Year</option>
                    </select>
                </div>

                {/* Stat Cards */}
                <div className="admin-stats-grid"> {/* Ensure classes exist */}
                    <StatCard title="Total Users" value={stats.totalUsers} icon={<Users />} className="stat-users" />
                    <StatCard title="Total Donors" value={stats.totalDonors} icon={<HeartHandshake />} className="stat-donors" />
                    <StatCard title="Listings (Filtered Period)" value={stats.totalListings} icon={<Package />} className="stat-listings" />
                    <StatCard title="Active Listings (Overall)" value={stats.activeListings} icon={<CheckCircle />} className="stat-active" />
                </div>


                {/* Listings Table */}
                <div className="admin-tables-container"> {/* Ensure class exists */}
                    {/* Show loading overlay or indicator when refetching based on filter */}
                    {isLoading && <div className="loading-overlay"><Loader2 className="spinner-inline" /> Loading listings...</div>}
                    <ListingListTable listings={listings} onDelete={handleDeleteListing} />
                </div>
            </div>
        </PageWrapper>
    );
}

