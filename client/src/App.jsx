import React, {
    useState,
    useEffect,
    createContext,
    useContext,
    useMemo,
    useRef,
    useCallback, // Import useCallback
} from 'react';
import "./App.css"
import {
    // --- React Router Imports ---
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
    Users,
    Package,
    CheckCircle,
    LogIn,
    LogOut,
    UserPlus,
    LayoutDashboard,
    PlusCircle,
    Trash2,
    AlertCircle,
    X,
    Loader2,
    UtensilsCrossed,
    HeartHandshake,
    CalendarDays,
    Clock,
    MapPin,
    List,
    Users2,
    ClipboardList,
    Edit3
} from 'lucide-react';

// CSS is imported in main.jsx
const BACKEND_URL = 'http://localhost:3001/api';

// --- Authentication Context ---
const AuthContext = createContext(null);

function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(localStorage.getItem('token'));
    const [role, setRole] = useState(localStorage.getItem('role'));
    const [isLoading, setIsLoading] = useState(true);
    
    // 1. useNavigate hook to control navigation from within the provider
    const navigate = useNavigate();

    // 2. Wrap redirectToDashboard in useCallback
    const redirectToDashboard = useCallback((userRole) => {
        if (userRole === 'Admin') navigate('/admin');
        else if (userRole === 'Donor') navigate('/donor');
        else if (userRole === 'Receiver') navigate('/receiver');
        else navigate('/login');
    }, [navigate]); // Add navigate as a dependency

    useEffect(() => {
        const storedToken = localStorage.getItem('token');
        const storedUser = localStorage.getItem('user');

        if (storedToken && storedUser) {
            try {
                const parsedUser = JSON.parse(storedUser);
                setToken(storedToken);
                setUser(parsedUser);
                setRole(parsedUser.role);
                // Don't navigate here, let the Route components handle the initial render
            } catch (e) {
                console.error("Failed to parse stored user:", e);
                // Call the new logout function
                logout();
            }
        }
        setIsLoading(false);
    }, []); // Empty dependency array, runs once on mount

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

    // 3. Wrap login in useCallback
    const login = useCallback(async (email, password) => {
        const { token, user } = await apiLogin(email, password);
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(user));
        setToken(token);
        setUser(user);
        setRole(user.role);
        redirectToDashboard(user.role);
    }, [redirectToDashboard]); // Add redirectToDashboard

    // 4. Wrap register in useCallback
    const register = useCallback(async (name, email, password, role) => {
        const { token, user } = await apiRegister(name, email, password, role);
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(user));
        setToken(token);
        setUser(user);
        setRole(user.role);
        redirectToDashboard(user.role);
    }, [redirectToDashboard]); // Add redirectToDashboard

    // 5. Wrap logout in useCallback
    const logout = useCallback(() => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        localStorage.removeItem('role');
        setToken(null);
        setUser(null);
        setRole(null);
        navigate('/login');
    }, [navigate]); // Add navigate

    const value = useMemo(
        () => ({
            user, token, role, isLoggedIn: !!token, isLoading,
            login, logout, register,
            // 6. Remove currentPage/setCurrentPage
        }), 
        // 7. Update dependencies
        [user, token, role, isLoading, login, logout, register]
    );

    return (
        <AuthContext.Provider value={value}>
            {!isLoading && children}
        </AuthContext.Provider>
    );
}

function useAuth() {
    const context = useContext(AuthContext);
    if (!context) throw new Error('useAuth must be used within an AuthProvider');
    return context;
}

// --- Main App Component ---
// This component now contains the Router logic
export default function App() {
    // Get location for AnimatePresence to work with Routes
    const location = useLocation();
    
    return (
        // AuthProvider is now wrapped by BrowserRouter in main.jsx
        <AuthProvider>
            <Header />
            <main>
                <AnimatePresence mode="wait">
                    {/* Pass location and key to Routes */}
                    <Routes location={location} key={location.pathname}>
                        <Route path="/" element={<HomeNavigation />} />
                        
                        {/* Public Routes */}
                        <Route path="/login" element={<LoginPage />} />
                        <Route path="/register" element={<RegisterPage />} />
                        
                        {/* Protected Routes */}
                        <Route 
                            path="/donor" 
                            element={
                                <ProtectedRoute>
                                    <DonorDashboard />
                                </ProtectedRoute>
                            } 
                        />
                        <Route 
                            path="/receiver" 
                            element={
                                <ProtectedRoute>
                                    <ReceiverDashboard />
                                </ProtectedRoute>
                            } 
                        />
                        <Route 
                            path="/admin" 
                            element={
                                <ProtectedRoute allowedRoles={['Admin']}>
                                    <AdminDashboard />
                                </ProtectedRoute>
                            } 
                        />

                        {/* Fallback route */}
                        <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                </AnimatePresence>
            </main>
        </AuthProvider>
    );
}

// --- Route Handling Components ---

// This component checks if a user is logged in
// If not, it redirects to the /login page
function ProtectedRoute({ children, allowedRoles }) {
    const { isLoggedIn, role } = useAuth();

    if (!isLoggedIn) {
        // Redirect them to the /login page, but save the current location they were
        // trying to go to. We don't use this in this app, but it's good practice.
        return <Navigate to="/login" replace />;
    }

    // If allowedRoles is provided, check if the user's role is in the list
    if (allowedRoles && !allowedRoles.includes(role)) {
        // Redirect to their default dashboard (or a "not authorized" page)
        return <Navigate to="/" replace />;
    }

    return children;
}

// This component handles the root "/" path
// It navigates the user to their correct dashboard if logged in,
// or to the login page if not.
function HomeNavigation() {
    const { isLoggedIn, role } = useAuth();
    
    if (isLoggedIn) {
        if (role === 'Admin') return <Navigate to="/admin" replace />;
        if (role === 'Donor') return <Navigate to="/donor" replace />;
        if (role === 'Receiver') return <Navigate to="/receiver" replace />;
    }
    
    return <Navigate to="/login" replace />;
}


// --- Reusable UI Components (PageWrapper, AuthCard, Input, Select, Button, Messages) ---
// (These components remain unchanged)
function PageWrapper({ children }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
            className="page-wrapper"
        >
            {children}
        </motion.div>
    );
}

function AuthCard({ title, children }) {
    return (
        <div className="auth-page-wrapper">
            <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="auth-card"
            >
                <div className="auth-card-header">
                    <motion.div
                        animate={{ rotate: [0, 15, -10, 15, 0] }}
                        transition={{ duration: 1, delay: 0.2 }}
                        className="auth-card-icon"
                    >
                        <HeartHandshake style={{ height: '100%', width: '100%' }} />
                    </motion.div>
                    <h2 className="auth-card-title">{title}</h2>
                </div>
                {children}
            </motion.div>
        </div>
    );
}

const Input = React.forwardRef(({ id, name, type, placeholder, ...props }, ref) => (
    <div>
        <label htmlFor={id} className="sr-only">{placeholder}</label>
        <input ref={ref} id={id} name={name} type={type} required className="form-input" placeholder={placeholder} {...props} />
    </div>
));
Input.displayName = 'Input'; // Add display name for React DevTools

const Select = React.forwardRef(({ id, name, children, ...props }, ref) => (
    <div>
        <label htmlFor={id} className="sr-only">{name}</label>
        <select ref={ref} id={id} name={name} required className="form-select" {...props}>
            {children}
        </select>
    </div>
));
Select.displayName = 'Select'; // Add display name for React DevTools

function Button({ children, type = 'button', onClick, className = '', isLoading = false, ...props }) {
    return (
        <motion.button
            type={type}
            onClick={onClick}
            disabled={isLoading}
            className={`button ${className}`}
            whileHover={{ scale: 1.03, transition: { duration: 0.2 } }}
            whileTap={{ scale: 0.98 }}
            {...props}
        >
            {isLoading ? <Loader2 className="spinner-inline" /> : children}
        </motion.button>
    );
}

// --- Header ---
function Header() {
    // 8. Get navigate hook
    const { isLoggedIn, role, logout, user } = useAuth();
    const navigate = useNavigate();
    
    return (
        <nav className="header-nav">
            <div className="header-container">
                <div className="header-logo">
                    {/* 9. Make logo a Link */}
                    <Link to="/" className="header-logo-link">
                        <UtensilsCrossed className="header-logo-icon" />
                        <span className="header-logo-text">LeftoverLink</span>
                    </Link>
                </div>
                <div className="header-links">
                    {isLoggedIn ? (
                        <>
                            <span className="header-user-greeting">Hi, <span>{user?.name}</span> {role === 'Admin' && '(Admin)'}</span>
                            <HeaderButton
                                // 10. Use navigate for dashboard button
                                onClick={() => {
                                    if (role === 'Admin') navigate('/admin');
                                    if (role === 'Donor') navigate('/donor');
                                    if (role === 'Receiver') navigate('/receiver');
                                }}
                                icon={<LayoutDashboard className="header-button-icon" />}
                            >
                                Dashboard
                            </HeaderButton>
                            {/* 11. Logout function now handles navigation */}
                            <HeaderButton onClick={logout} icon={<LogOut className="header-button-icon" />} className="logout">
                                Logout
                            </HeaderButton>
                        </>
                    ) : (
                        <>
                            {/* 12. Use navigate for Login/Register */}
                            <HeaderButton onClick={() => navigate('/login')} icon={<LogIn className="header-button-icon" />}>
                                Login
                            </HeaderButton>
                            <HeaderButton onClick={() => navigate('/register')} icon={<UserPlus className="header-button-icon" />} className="register">
                                Register
                            </HeaderButton>
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
            className={`header-button ${className}`}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
        >
            {icon}
            <span>{children}</span>
        </motion.button>
    );
}

// --- Message & Spinner Components (Unchanged) ---
function ErrorMessage({ message, onDismiss }) {
    if (!message) return null;
    return (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="message-base error-message" role="alert">
            <div className="message-content">
                <AlertCircle className="message-icon" />
                <span>{message}</span>
            </div>
            {onDismiss && <button onClick={onDismiss} className="message-dismiss-button"><X className="message-icon" /></button>}
        </motion.div>
    );
}

function SuccessMessage({ message, onDismiss }) {
    if (!message) return null;
    return (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="message-base success-message" role="alert">
            <div className="message-content">
                <CheckCircle className="message-icon" />
                <span>{message}</span>
            </div>
            {onDismiss && <button onClick={onDismiss} className="message-dismiss-button"><X className="message-icon" /></button>}
        </motion.div>
    );
}

function LoadingSpinner() {
    return <div className="spinner-page-wrapper"><Loader2 className="spinner-page" /></div>;
}

// --- API Helper Hook (Unchanged) ---
function useApi() {
    const { token, logout } = useAuth();
    
    // Helper function for standard JSON fetches
    const jsonFetch = async (endpoint, options = {}) => {
        const headers = { 'Content-Type': 'application/json', ...options.headers };
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        const response = await fetch(`${BACKEND_URL}${endpoint}`, { ...options, headers });
        return handleResponse(response);
    };

    // Helper function for FormData fetches (used for file uploads)
    const formFetch = async (endpoint, formData, method = 'POST') => {
        const headers = {}; // Content-Type is set automatically by browser for FormData
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        const response = await fetch(`${BACKEND_URL}${endpoint}`, {
            method: method,
            headers: headers,
            body: formData,
        });
        return handleResponse(response);
    };

    const handleResponse = async (response) => {
        if (response.status === 401) {
            logout();
            throw new Error('Your session has expired. Please log in again.');
        }
        const data = await response.json().catch(() => ({})); // Handle non-JSON response gracefully
        if (!response.ok) {
            throw new Error(data.message || 'An API error occurred');
        }
        return data;
    }
    
    return { jsonFetch, formFetch };
}


// --- Auth Pages (Login, Register) ---
function LoginPage() {
    const { login } = useAuth();
    // const navigate = useNavigate(); // Not needed, login function handles nav
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [isAdminLoading, setIsAdminLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsLoading(true);
        try {
            // login() now handles navigation on success
            await login(email, password);
        } catch (err) {
            setError(err.message); 
            setIsLoading(false);
        }
    };

    const handleAdminLogin = async () => {
        setError(null);
        setIsAdminLoading(true);
        try {
            // NOTE: Hardcoded admin credentials for demo purposes
            await login("admin@gmail.com", "adminbalu"); 
        } catch (err) {
            setError("Admin login failed. Check credentials or server.");
            setIsAdminLoading(false);
        }
    };

    return (
        <PageWrapper>
            <AuthCard title="Sign in to your account">
                <form className="auth-form" onSubmit={handleSubmit}>
                    <div className="auth-form-inputs">
                        <AnimatePresence>
                            <ErrorMessage message={error} onDismiss={() => setError(null)} />
                        </AnimatePresence>
                        <Input id="email-address" name="email" type="email" autoComplete="email" placeholder="Email address" value={email} onChange={(e) => setEmail(e.target.value)} />
                        <Input id="password" name="password" type="password" autoComplete="current-password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
                    </div>
                    <Button type="submit" isLoading={isLoading}><LogIn className="button-icon" />Sign in</Button>
                    <div className="auth-form-footer">
                        {/* 13. Change button to Link */}
                        <Link to="/register">Need an account? Register</Link>
                    </div>

                    <Button
                        type="button"
                        className="button-admin-login"
                        isLoading={isAdminLoading}
                        onClick={handleAdminLogin}
                    >
                        <Users className="button-icon" />
                        Login as Admin
                    </Button>
                </form>
            </AuthCard>
        </PageWrapper>
    );
}

function RegisterPage() {
    const { register } = useAuth();
    // const navigate = useNavigate(); // Not needed, register handles nav
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [role, setRole] = useState('Receiver');
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (email === "admin@gmail.com") {
            setError("This email is reserved. Please use another.");
            return;
        }
        setError(null);
        setIsLoading(true);
        try {
            // register() now handles navigation on success
            await register(name, email, password, role);
        } catch (err) {
            setError(err.message);
            setIsLoading(false);
        }
    };

    return (
        <PageWrapper>
            <AuthCard title="Create your account">
                <form className="auth-form" onSubmit={handleSubmit}>
                    <div className="auth-form-inputs">
                        <AnimatePresence>
                            <ErrorMessage message={error} onDismiss={() => setError(null)} />
                        </AnimatePresence>
                        <Input id="name" name="name" type="text" placeholder="Full Name" value={name} onChange={(e) => setName(e.target.value)} />
                        <Input id="email-address" name="email" type="email" autoComplete="email" placeholder="Email address" value={email} onChange={(e) => setEmail(e.target.value)} />
                        <Input id="password" name="password" type="password" autoComplete="new-password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
                        <Select id="role" name="role" value={role} onChange={(e) => setRole(e.target.value)}>
                            <option value="Receiver">I am a Receiver</option>
                            <option value="Donor">I am a Donor</option>
                        </Select>
                    </div>
                    <Button type="submit" isLoading={isLoading}><UserPlus className="button-icon" />Create Account</Button>
                    <div className="auth-form-footer">
                        {/* 14. Change button to Link */}
                        <Link to="/login">Already have an account? Sign in</Link>
                    </div>
                </form>
            </AuthCard>
        </PageWrapper>
    );
}


// --- Shared UI Component: FormInput (Unchanged) ---
const FormInput = React.forwardRef(({ 
    label, 
    id, 
    type = 'text', 
    placeholder, 
    value, 
    onChange, 
    required = false, 
    min, 
    ...props 
}, ref) => {
    
    // Determine input element based on type
    const InputElement = type === 'textarea' ? 'textarea' : 'input';

    return (
        <div className="form-group">
            <label htmlFor={id} className="form-label">{label}</label>
            <InputElement
                ref={ref}
                id={id}
                name={id}
                type={type}
                placeholder={placeholder}
                value={type !== 'file' ? value : undefined}
                onChange={type !== 'file' ? onChange : undefined}
                required={required}
                min={min}
                className={type === 'textarea' ? "form-textarea" : "form-input"}
                {...props}
            />
        </div>
    );
});
FormInput.displayName = 'FormInput';

// --- Shared UI Component: FoodCard (Unchanged) ---
function FoodCard({ listing, onDelete, onEdit, showDelete, showEdit, onClaim }) {
    const { user } = useAuth();
    const isExpired = new Date(listing.expiryTime) < new Date();
    const isFullyClaimed = listing.claims.length >= listing.maxClaims;
    const isClaimedByUser = user && listing.claims.some(claim => claim.userId.toString() === user._id.toString());
    const remainingClaims = listing.maxClaims - listing.claims.length;

    return (
        <motion.div 
            className={`food-card ${isExpired ? 'card-expired' : ''} ${isFullyClaimed && !isExpired ? 'card-fully-claimed' : ''}`}
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
        >
            <div className="card-image-container">
                <img 
                    src={listing.imageUrl || 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image'} 
                    alt={listing.description} 
                    className="card-image"
                />
                {(isExpired || isFullyClaimed) && (
                    <div className="card-status-overlay">
                        {isExpired ? 'EXPIRED' : 'FULLY CLAIMED'}
                    </div>
                )}
            </div>
            <div className="card-content">
                <h3 className="card-title">{listing.description}</h3>
                <div className="card-details">
                    <p><Package className="detail-icon" /> Quantity: <strong>{listing.quantity}</strong></p>
                    <p><MapPin className="detail-icon" /> Location: <strong>{listing.location}</strong></p>
                    <p><CalendarDays className="detail-icon" /> Expiry: <strong>{new Date(listing.expiryTime).toLocaleString()}</strong></p>
                    <p><Users2 className="detail-icon" /> Slots: <strong>{remainingClaims} of {listing.maxClaims} remaining</strong></p>
                    
                    {onClaim && (
                        <p className={isClaimedByUser ? 'claimed-status' : 'unclaimed-status'}>
                            {isClaimedByUser ? (<><CheckCircle className="detail-icon" /> Claimed by you!</>) : ''}
                        </p>
                    )}
                    
                    {(showDelete || showEdit) && (
                        <div className="card-claims-list">
                            <p style={{marginTop:'0.5rem', fontWeight:'bold'}}>Current Claims ({listing.claims.length}):</p>
                            <ul>
                                {listing.claims.map((claim, index) => (
                                    <li key={index}>{claim.name}</li>
                                ))}
                                {listing.claims.length === 0 && <li>No claims yet.</li>}
                            </ul>
                        </div>
                    )}
                </div>
            </div>
            <div className="card-actions">
                {onClaim && (
                    <Button 
                        onClick={onClaim}
                        disabled={isExpired || isFullyClaimed || isClaimedByUser}
                        className="button-claim"
                        
                    >
                        {isClaimedByUser ? 'Already Claimed' : (isFullyClaimed ? 'Fully Claimed' : 'Claim Food')}
                    </Button>
                )}
                
                {(showEdit && onEdit) && (
                    <Button onClick={onEdit} className="button-secondary button-edit-delete"><Edit3 /></Button>
                )}
                
                {(showDelete && onDelete) && (
                    <Button onClick={onDelete} className="button-danger button-edit-delete"><Trash2 /></Button>
                )}
            </div>
        </motion.div>
    );
}

// --- Donor Dashboard Components (Add/Edit) (Unchanged) ---
function AddFoodListingForm({ onListingCreated }) {
    const [description, setDescription] = useState('');
    const [quantity, setQuantity] = useState('');
    const [location, setLocation] = useState('');
    const [mfgTime, setMfgTime] = useState('');
    const [expiryTime, setExpiryTime] = useState('');
    const [maxClaims, setMaxClaims] = useState(1);
    const imageRef = useRef(null);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const { formFetch } = useApi();

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (maxClaims < 1) {
            setError("Maximum claims must be 1 or more.");
            return;
        }
        setError(null);
        setSuccess(null);
        setIsLoading(true);

        const formData = new FormData();
        formData.append('description', description);
        formData.append('quantity', quantity);
        formData.append('location', location);
        formData.append('mfgTime', mfgTime);
        formData.append('expiryTime', expiryTime);
        formData.append('maxClaims', maxClaims);
        
        if (imageRef.current && imageRef.current.files[0]) {
            formData.append('image', imageRef.current.files[0]);
        }
        
        try {
            await formFetch('/food', formData, 'POST');
            setSuccess('Listing created successfully!');
            
            // Reset form fields
            setDescription(''); setQuantity(''); setLocation(''); setMfgTime(''); setExpiryTime(''); setMaxClaims(1);
            if (imageRef.current) imageRef.current.value = null;

            onListingCreated();
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <motion.div className="add-food-form-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <h2>Create New Food Listing</h2>
            <form onSubmit={handleSubmit}>
                <AnimatePresence>
                    <ErrorMessage message={error} onDismiss={() => setError(null)} />
                    <SuccessMessage message={success} onDismiss={() => setSuccess(null)} />
                </AnimatePresence>
                
                <FormInput label="Description" id="description" type="text" placeholder="e.g., 10 vegetable curry meals" value={description} onChange={(e) => setDescription(e.target.value)} required={true} />
                
                <div className="form-group-grid">
                    <FormInput label="Quantity" id="quantity" type="text" placeholder="e.g., 10 packets, 5 kg" value={quantity} onChange={(e) => setQuantity(e.target.value)} required={true} />
                    <FormInput label="Maximum Claims" id="maxClaims" type="number" min="1" placeholder="1" value={maxClaims} onChange={(e) => setMaxClaims(parseInt(e.target.value, 10) || 1)} required={true} />
                </div>
                
                <FormInput label="Pickup Location" id="location" type="text" placeholder="Full address" value={location} onChange={(e) => setLocation(e.target.value)} required={true} />
                
                <FormInput label="Image File" id="image" type="file" ref={imageRef} accept="image/*" required={false} /> 
                
                <div className="form-group-grid">
                    <FormInput label="Manufacture Time" id="mfgTime" type="datetime-local" value={mfgTime} onChange={(e) => setMfgTime(e.target.value)} required={true} />
                    <FormInput label="Expiry Time" id="expiryTime" type="datetime-local" value={expiryTime} onChange={(e) => setExpiryTime(e.target.value)} required={true} />
                </div>
                
                <div style={{ marginTop: '1.5rem' }}>
                    <Button type="submit" isLoading={isLoading}><PlusCircle className="button-icon" />Add Listing</Button>
                </div>
            </form>
        </motion.div>
    );
}

function EditFoodListingForm({ listing, onListingUpdated, onCancel }) {
    const formatDate = (dateString) => {
        const date = new Date(dateString);
        return date.toISOString().slice(0, 16);
    };
    
    const [description, setDescription] = useState(listing.description);
    const [quantity, setQuantity] = useState(listing.quantity);
    const [location, setLocation] = useState(listing.location);
    const [mfgTime, setMfgTime] = useState(formatDate(listing.mfgTime));
    const [expiryTime, setExpiryTime] = useState(formatDate(listing.expiryTime));
    const [maxClaims, setMaxClaims] = useState(listing.maxClaims);
    const imageRef = useRef(null);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const { formFetch } = useApi();

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (maxClaims < 1) {
            setError("Maximum claims must be 1 or more.");
            return;
        }
        setError(null);
        setSuccess(null);
        setIsLoading(true);

        const formData = new FormData();
        formData.append('description', description);
        formData.append('quantity', quantity);
        formData.append('location', location);
        formData.append('mfgTime', mfgTime);
        formData.append('expiryTime', expiryTime);
        formData.append('maxClaims', maxClaims);
        
        if (imageRef.current && imageRef.current.files[0]) {
            formData.append('image', imageRef.current.files[0]);
        }
        
        try {
            const updatedListing = await formFetch(`/food/${listing._id}`, formData, 'PUT');
            setSuccess('Listing updated successfully!');
            onListingUpdated(updatedListing);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <motion.div className="add-food-form-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <h2>Edit Food Listing: {listing.description}</h2>
            <form onSubmit={handleSubmit}>
                <AnimatePresence>
                    <ErrorMessage message={error} onDismiss={() => setError(null)} />
                    <SuccessMessage message={success} onDismiss={() => setSuccess(null)} />
                </AnimatePresence>
                
                <FormInput label="Description" id="description-edit" type="text" placeholder="e.g., 10 vegetable curry meals" value={description} onChange={(e) => setDescription(e.target.value)} required={true} />
                
                <div className="form-group-grid">
                    <FormInput label="Quantity" id="quantity-edit" type="text" placeholder="e.g., 10 packets, 5 kg" value={quantity} onChange={(e) => setQuantity(e.target.value)} required={true} />
                    <FormInput label="Maximum Claims" id="maxClaims-edit" type="number" min="1" placeholder="1" value={maxClaims} onChange={(e) => setMaxClaims(parseInt(e.target.value, 10) || 1)} required={true} />
                </div>
                
                <FormInput label="Pickup Location" id="location-edit" type="text" placeholder="Full address" value={location} onChange={(e) => setLocation(e.target.value)} required={true} />
                
                <FormInput 
                    label="Image File (Leave blank to keep current)" 
                    id="image-edit" 
                    type="file" 
                    ref={imageRef} 
                    accept="image/*" 
                    required={false} 
                />
                
                {listing.imageUrl && <p style={{marginTop:'0.5rem', fontSize:'0.9rem', paddingLeft: '0.2rem'}}>Current Image: <a href={listing.imageUrl} target="_blank" rel="noopener noreferrer">View</a></p>}

                <div className="form-group-grid">
                    <FormInput label="Manufacture Time" id="mfgTime-edit" type="datetime-local" value={mfgTime} onChange={(e) => setMfgTime(e.target.value)} required={true} />
                    <FormInput label="Expiry Time" id="expiryTime-edit" type="datetime-local" value={expiryTime} onChange={(e) => setExpiryTime(e.target.value)} required={true} />
                </div>
                
                <div style={{ marginTop: '1.5rem', display: 'flex', gap: '1rem' }}>
                    <Button type="submit" isLoading={isLoading} className="button-primary"><Edit3 className="button-icon" />Update Listing</Button>
                    <Button type="button" onClick={onCancel} className="button-secondary">Cancel</Button>
                </div>
            </form>
        </motion.div>
    );
}

// -------------------------------------------------------------------------------- //
// --- 3. Donor Dashboard (COMPLETED) (Unchanged) ---
// -------------------------------------------------------------------------------- //
function DonorDashboard() {
    const [view, setView] = useState('view');
    const [listingToEdit, setListingToEdit] = useState(null);
    const [myListings, setMyListings] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [successMessage, setSuccessMessage] = useState(null);
    const { jsonFetch } = useApi();

    const fetchMyListings = async () => {
        setIsLoading(true);
        setError(null);
        try {
            // API call to fetch donor's own listings
            const data = await jsonFetch('/food/donor/me'); 
            setMyListings(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    const handleListingCreatedOrUpdated = () => {
        setView('view'); // Switch back to view mode after success
        setListingToEdit(null); // Clear editing state
        fetchMyListings(); // Refresh the list
    };

    const handleDeleteListing = async (listingId) => {
        if (!window.confirm("Are you sure you want to delete this food listing? This action cannot be undone.")) return;
        
        setError(null);
        setSuccessMessage(null);
        setIsLoading(true);

        try {
            await jsonFetch(`/food/${listingId}`, { method: 'DELETE' });
            setSuccessMessage('Listing deleted successfully!');
            fetchMyListings(); // Full refresh
        } catch (err) {
            setError(err.message);
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchMyListings();
    }, []);

    const renderContent = () => {
        if (view === 'add') {
            return (
                <AddFoodListingForm 
                    onListingCreated={() => {
                        setSuccessMessage('Listing created successfully!');
                        handleListingCreatedOrUpdated();
                    }} 
                />
            );
        }
        
        if (view === 'edit' && listingToEdit) {
            return (
                <EditFoodListingForm 
                    listing={listingToEdit}
                    onListingUpdated={(updatedListing) => {
                        setSuccessMessage('Listing updated successfully!');
                        // Optimistically update the list with the new data
                        setMyListings(myListings.map(l => l._id === updatedListing._id ? updatedListing : l));
                        handleListingCreatedOrUpdated();
                    }}
                    onCancel={() => setView('view')}
                />
            );
        }

        // Default view: list of donor's food listings
        if (isLoading) return <LoadingSpinner />;
        
        return (
            <>
                <div className="dashboard-actions">
                    <Button onClick={() => setView('add')} className="button-success">
                        <PlusCircle className="button-icon" /> Add New Listing
                    </Button>
                </div>
                
                <AnimatePresence>
                    <ErrorMessage message={error} onDismiss={() => setError(null)} />
                    <SuccessMessage message={successMessage} onDismiss={() => setSuccessMessage(null)} />
                </AnimatePresence>
                
                <h2 className="dashboard-title">My Current Food Listings</h2>

                {myListings.length === 0 ? (
                    <div className="empty-state">
                        <Package />
                        <p>You haven't posted any food listings yet. Start sharing!</p>
                    </div>
                ) : (
                    <div className="food-list-grid">
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
            <h1 className="page-header"><HeartHandshake className="header-icon" /> Donor Dashboard</h1>
            <div className="dashboard-container">
                {renderContent()}
            </div>
        </PageWrapper>
    );
}

// -------------------------------------------------------------------------------- //
// --- 4. Receiver Dashboard (COMPLETED) (Unchanged) ---
// -------------------------------------------------------------------------------- //
function ReceiverDashboard() {
    const { user } = useAuth();
    const [allListings, setAllListings] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [successMessage, setSuccessMessage] = useState(null);
    const { jsonFetch } = useApi();

    const fetchAllListings = async () => {
        setIsLoading(true);
        setError(null);
        try {
            // API call to fetch all available food listings
            const data = await jsonFetch('/food'); 
            // Filter out listings posted by the current user (if a receiver somehow has a listing)
            const availableListings = data.filter(listing => listing.donorId !== user._id);
            setAllListings(availableListings);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    const handleClaimFood = async (listingId) => {
        setError(null);
        setSuccessMessage(null);
        
        const listing = allListings.find(l => l._id === listingId);
        if (!listing || listing.claims.some(claim => claim.userId === user._id) || listing.claims.length >= listing.maxClaims) {
            setError("Cannot claim this listing.");
            return;
        }

        try {
            // POST request to claim endpoint
            const data = await jsonFetch(`/food/${listingId}/claim`, { method: 'POST' });
            setSuccessMessage('Food claimed successfully! Check with the donor for pickup details.');
            
            // Optimistically update the listing's claims in the state
            setAllListings(prevListings => 
                prevListings.map(l => l._id === listingId ? data : l)
            );
        } catch (err) {
            setError(err.message);
        }
    };

    useEffect(() => {
        fetchAllListings();
    }, []);

    if (isLoading) return <LoadingSpinner />;

    return (
        <PageWrapper>
            <h1 className="page-header"><List className="header-icon" /> Available Food Listings</h1>
            <div className="dashboard-container">
                <AnimatePresence>
                    <ErrorMessage message={error} onDismiss={() => setError(null)} />
                    <SuccessMessage message={successMessage} onDismiss={() => setSuccessMessage(null)} />
                </AnimatePresence>
                
                <p className="page-intro">Browse the food donations available near you. Claim a slot to arrange pickup!</p>

                {allListings.length === 0 && !error ? (
                    <div className="empty-state">
                        <Package />
                        <p>No active food listings are available right now. Check back soon!</p>
                    </div>
                ) : (
                    <div className="food-list-grid">
                        <AnimatePresence>
                            {allListings.map(listing => (
                                <FoodCard 
                                    key={listing._id}
                                    listing={listing}
                                    onClaim={() => handleClaimFood(listing._id)}
                                />
                            ))}
                        </AnimatePresence>
                    </div>
                )}
            </div>
        </PageWrapper>
    );
}

// -------------------------------------------------------------------------------- //
// --- 5. Admin Dashboard (COMPLETED) (Unchanged) ---
// -------------------------------------------------------------------------------- //
function StatCard({ title, value, icon, className }) {
    return (
        <motion.div className={`stat-card ${className}`} whileHover={{ scale: 1.02 }}>
            <div className="stat-icon-container">{icon}</div>
            <div className="stat-content">
                <p className="stat-value">{value}</p>
                <h3 className="stat-title">{title}</h3>
            </div>
        </motion.div>
    );
}

function UserListTable({ users }) {
    return (
        <div className="admin-table-card">
            <h3>Registered Users</h3>
            <div className="table-wrapper">
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Registered</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map(user => (
                            <tr key={user._id}>
                                <td>{user.name}</td>
                                <td>{user.email}</td>
                                <td><span className={`role-tag role-${user.role.toLowerCase()}`}>{user.role}</span></td>
                                <td>{new Date(user.createdAt).toLocaleDateString()}</td>
                            </tr>
                        ))}
                        {users.length === 0 && <tr><td colSpan="4">No users found.</td></tr>}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function ListingListTable({ listings, onDelete }) {
    return (
        <div className="admin-table-card">
            <h3>All Food Listings</h3>
            <div className="table-wrapper">
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Description</th>
                            <th>Donor</th>
                            <th>Status</th>
                            <th>Expires</th>
                            <th>Claims</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {listings.map(listing => {
                            const isExpired = new Date(listing.expiryTime) < new Date();
                            const isFullyClaimed = listing.claims.length >= listing.maxClaims;
                            return (
                                <tr key={listing._id} className={isExpired ? 'expired-row' : ''}>
                                    <td>{listing.description}</td>
                                    <td>{listing.donorName || 'N/A'}</td>
                                    <td>
                                        {isExpired ? <span className="status-tag status-expired">Expired</span> : 
                                         (isFullyClaimed ? <span className="status-tag status-claimed">Full</span> : 
                                         <span className="status-tag status-active">Active</span>)}
                                    </td>
                                    <td>{new Date(listing.expiryTime).toLocaleString()}</td>
                                    <td>{listing.claims.length}/{listing.maxClaims}</td>
                                    <td>
                                        <Button onClick={() => onDelete(listing._id)} className="button-icon-only button-danger" title="Delete Listing">
                                            <Trash2 />
                                        </Button>
                                    </td>
                                </tr>
                            );
                        })}
                        {listings.length === 0 && <tr><td colSpan="6">No listings found.</td></tr>}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function AdminDashboard() {
    const [users, setUsers] = useState([]);
    const [listings, setListings] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [successMessage, setSuccessMessage] = useState(null);
    const { jsonFetch } = useApi();

    const fetchData = async () => {
        setIsLoading(true);
        setError(null);
        try {
            // Fetch All Users - Requires Admin endpoint
            const usersData = await jsonFetch('/admin/users');
            setUsers(usersData);

            // Fetch All Listings - Requires Admin endpoint
            const listingsData = await jsonFetch('/admin/food');
            setListings(listingsData);

        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    const handleDeleteListing = async (listingId) => {
        if (!window.confirm("Admin: Are you sure you want to delete this food listing?")) return;
        
        setError(null);
        setSuccessMessage(null);

        try {
            // Admin-specific DELETE endpoint
            await jsonFetch(`/admin/food/${listingId}`, { method: 'DELETE' });
            setSuccessMessage('Listing deleted successfully by Admin.');
            setListings(prev => prev.filter(l => l._id !== listingId)); // Optimistic update
        } catch (err) {
            setError(err.message);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    if (isLoading) return <LoadingSpinner />;

    return (
        <PageWrapper>
            <h1 className="page-header"><LayoutDashboard className="header-icon" /> Admin Dashboard</h1>
            <div className="dashboard-container admin-dashboard">
                <AnimatePresence>
                    <ErrorMessage message={error} onDismiss={() => setError(null)} />
                    <SuccessMessage message={successMessage} onDismiss={() => setSuccessMessage(null)} />
                </AnimatePresence>

                <div className="admin-stats-grid">
                    <StatCard title="Total Users" value={users.length} icon={<Users />} className="stat-users" />
                    <StatCard title="Total Donors" value={users.filter(u => u.role === 'Donor').length} icon={<HeartHandshake />} className="stat-donors" />
                    <StatCard title="Total Listings" value={listings.length} icon={<Package />} className="stat-listings" />
                    <StatCard title="Active Listings" value={listings.filter(l => new Date(l.expiryTime) > new Date()).length} icon={<CheckCircle />} className="stat-active" />
                </div>

                <div className="admin-tables-container">
                    <UserListTable users={users} />
                    <ListingListTable listings={listings} onDelete={handleDeleteListing} />
                </div>
            </div>
        </PageWrapper>
    );
}