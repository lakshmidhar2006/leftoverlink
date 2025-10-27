import React, {
    useState,
    useEffect,
    createContext,
    useContext,
    useMemo,
    useRef,
    useCallback,
} from 'react';
import "./App.css"; // Ensure App.css is in the src folder
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
    Users, // Still used for Stat Card icon
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
    MapPin,
    List,
    Users2,
    ClipboardList,
    Edit3,
    Download // Import Download icon
} from 'lucide-react';
// *** Import PDF generation libraries ***
import jsPDF from 'jspdf';
import 'jspdf-autotable';

// Use environment variables for production
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'https://leftovberlink.onrender.com/api';

// --- Authentication Context ---
const AuthContext = createContext(null);

function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(localStorage.getItem('token'));
    const [role, setRole] = useState(localStorage.getItem('role'));
    const [isLoading, setIsLoading] = useState(true);

    const navigate = useNavigate();

    const redirectToDashboard = useCallback((userRole) => {
        if (userRole === 'Admin') navigate('/admin');
        else if (userRole === 'Donor') navigate('/donor');
        else if (userRole === 'Receiver') navigate('/receiver');
        else navigate('/login');
    }, [navigate]);

    const logout = useCallback(() => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        localStorage.removeItem('role');
        setToken(null);
        setUser(null);
        setRole(null);
        navigate('/login');
    }, [navigate]);

    useEffect(() => {
        const storedToken = localStorage.getItem('token');
        const storedUser = localStorage.getItem('user');

        if (storedToken && storedUser) {
            try {
                const parsedUser = JSON.parse(storedUser);
                setToken(storedToken);
                setUser(parsedUser);
                setRole(parsedUser.role);
            } catch (e) {
                console.error("Failed to parse stored user:", e);
                logout();
            }
        }
        setIsLoading(false);
    }, [logout]);

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

    const login = useCallback(async (email, password) => {
        const { token, user } = await apiLogin(email, password);
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(user));
        setToken(token);
        setUser(user);
        setRole(user.role);
        redirectToDashboard(user.role);
    }, [redirectToDashboard]);

    const register = useCallback(async (name, email, password, role) => {
        const { token, user } = await apiRegister(name, email, password, role);
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(user));
        setToken(token);
        setUser(user);
        setRole(user.role);
        redirectToDashboard(user.role);
    }, [redirectToDashboard]);

    const value = useMemo(
        () => ({
            user, token, role, isLoggedIn: !!token, isLoading,
            login, logout, register,
        }),
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
export default function App() {
    const location = useLocation();

    return (
        <AuthProvider>
            <Header />
            <main>
                <AnimatePresence mode="wait">
                    <Routes location={location} key={location.pathname}>
                        <Route path="/" element={<HomeNavigation />} />
                        <Route path="/login" element={<LoginPage />} />
                        <Route path="/register" element={<RegisterPage />} />
                        <Route
                            path="/donor"
                            element={<ProtectedRoute allowedRoles={['Donor']}><DonorDashboard /></ProtectedRoute>}
                        />
                        <Route
                            path="/receiver"
                            element={<ProtectedRoute allowedRoles={['Receiver']}><ReceiverDashboard /></ProtectedRoute>}
                        />
                        <Route
                            path="/admin"
                            element={<ProtectedRoute allowedRoles={['Admin']}><AdminDashboard /></ProtectedRoute>}
                        />
                        <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                </AnimatePresence>
            </main>
        </AuthProvider>
    );
}

// --- Route Handling Components ---
function ProtectedRoute({ children, allowedRoles }) {
    const { isLoggedIn, role, isLoading } = useAuth(); // Added isLoading

    // If still loading auth state, don't render anything yet
    if (isLoading) {
        return <LoadingSpinner />; // Or null, or a minimal loading indicator
    }


    if (!isLoggedIn) {
        return <Navigate to="/login" replace />;
    }
    if (allowedRoles && !allowedRoles.includes(role)) {
        return <Navigate to="/" replace />;
    }
    return children;
}

function HomeNavigation() {
    const { isLoggedIn, role, isLoading } = useAuth(); // Added isLoading

     // Wait for auth state to load
     if (isLoading) {
        return <LoadingSpinner />;
    }

    if (isLoggedIn) {
        if (role === 'Admin') return <Navigate to="/admin" replace />;
        if (role === 'Donor') return <Navigate to="/donor" replace />;
        if (role === 'Receiver') return <Navigate to="/receiver" replace />;
    }
    return <Navigate to="/login" replace />;
}


// --- Reusable UI Components (PageWrapper, AuthCard, Input, Select, Button, Messages) ---
// (No changes needed in these components)
function PageWrapper({ children }) {
    return (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }} className="page-wrapper">
            {children}
        </motion.div>
    );
}
function AuthCard({ title, children }) {
    return (
        <div className="auth-page-wrapper">
            <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} className="auth-card">
                <div className="auth-card-header">
                    <motion.div animate={{ rotate: [0, 15, -10, 15, 0] }} transition={{ duration: 1, delay: 0.2 }} className="auth-card-icon">
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
Input.displayName = 'Input';
const Select = React.forwardRef(({ id, name, children, ...props }, ref) => (
    <div>
        <label htmlFor={id} className="sr-only">{name}</label>
        <select ref={ref} id={id} name={name} required className="form-select" {...props}>
            {children}
        </select>
    </div>
));
Select.displayName = 'Select';
function Button({ children, type = 'button', onClick, className = '', isLoading = false, ...props }) {
    return (
        <motion.button type={type} onClick={onClick} disabled={isLoading} className={`button ${className}`} whileHover={{ scale: 1.03, transition: { duration: 0.2 } }} whileTap={{ scale: 0.98 }} {...props}>
            {isLoading ? <Loader2 className="spinner-inline" /> : children}
        </motion.button>
    );
}
function Header({ /* No changes needed */ }) {
    const { isLoggedIn, role, logout, user } = useAuth();
    const navigate = useNavigate();
    return (
        <nav className="header-nav">
            <div className="header-container">
                <div className="header-logo"><Link to="/" className="header-logo-link"><UtensilsCrossed className="header-logo-icon" /><span className="header-logo-text">LeftoverLink</span></Link></div>
                <div className="header-links">
                    {isLoggedIn ? (
                        <>
                            <span className="header-user-greeting">Hi, <span>{user?.name}</span> {role === 'Admin' && '(Admin)'}</span>
                            <HeaderButton onClick={() => { if (role === 'Admin') navigate('/admin'); if (role === 'Donor') navigate('/donor'); if (role === 'Receiver') navigate('/receiver'); }} icon={<LayoutDashboard className="header-button-icon" />}>Dashboard</HeaderButton>
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
    return (<motion.button onClick={onClick} className={`header-button ${className}`} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>{icon}<span>{children}</span></motion.button>);
}
function ErrorMessage({ message, onDismiss }) {
    if (!message) return null;
    return (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="message-base error-message" role="alert">
            <div className="message-content"><AlertCircle className="message-icon" /><span>{message}</span></div>
            {onDismiss && <button onClick={onDismiss} className="message-dismiss-button"><X className="message-icon" /></button>}
        </motion.div>
    );
}
function SuccessMessage({ message, onDismiss }) {
    if (!message) return null;
    return (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="message-base success-message" role="alert">
            <div className="message-content"><CheckCircle className="message-icon" /><span>{message}</span></div>
            {onDismiss && <button onClick={onDismiss} className="message-dismiss-button"><X className="message-icon" /></button>}
        </motion.div>
    );
}
function LoadingSpinner() { return <div className="spinner-page-wrapper"><Loader2 className="spinner-page" /></div>; }
// --- API Helper Hook (No changes needed) ---
function useApi() {
    const { token, logout } = useAuth();
    const handleResponse = useCallback(async (response) => {
        if (response.status === 401) { logout(); throw new Error('Your session has expired. Please log in again.'); }
        const data = await response.json().catch(() => ({}));
        if (!response.ok) { throw new Error(data.message || 'An API error occurred'); }
        return data;
    }, [logout]);
    const jsonFetch = useCallback(async (endpoint, options = {}) => {
        const headers = { 'Content-Type': 'application/json', ...options.headers }; if (token) { headers['Authorization'] = `Bearer ${token}`; }
        const response = await fetch(`${BACKEND_URL}${endpoint}`, { ...options, headers }); return handleResponse(response);
    }, [token, handleResponse]);
    const formFetch = useCallback(async (endpoint, formData, method = 'POST') => {
        const headers = {}; if (token) { headers['Authorization'] = `Bearer ${token}`; }
        const response = await fetch(`${BACKEND_URL}${endpoint}`, { method: method, headers: headers, body: formData, }); return handleResponse(response);
    }, [token, handleResponse]);
    return { jsonFetch, formFetch };
}

// --- Auth Pages (Login, Register) ---
// *** LoginPage: Removed Admin Login Button ***
function LoginPage() {
    const { login } = useAuth();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsLoading(true);
        try {
            // Standard login handles all roles, including Admin
            await login(email, password);
        } catch (err) {
            setError(err.message);
            setIsLoading(false); // Only set loading false on error
        }
        // Don't set isLoading to false on success, as navigation will happen
    };

    return (
        <PageWrapper>
            <AuthCard title="Sign in to your account">
                <form className="auth-form" onSubmit={handleSubmit}>
                    <div className="auth-form-inputs">
                        <AnimatePresence>
                            <ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} />
                        </AnimatePresence>
                        <Input id="email-address" name="email" type="email" autoComplete="email" placeholder="Email address" value={email} onChange={(e) => setEmail(e.target.value)} />
                        <Input id="password" name="password" type="password" autoComplete="current-password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
                    </div>
                    <Button type="submit" isLoading={isLoading}><LogIn className="button-icon" />Sign in</Button>
                    <div className="auth-form-footer">
                        <Link to="/register">Need an account? Register</Link>
                    </div>
                    {/* Admin Login Button Removed */}
                </form>
            </AuthCard>
        </PageWrapper>
    );
}
// RegisterPage (No changes needed)
function RegisterPage() {
    const { register } = useAuth(); const [name, setName] = useState(''); const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [role, setRole] = useState('Receiver'); const [error, setError] = useState(null); const [isLoading, setIsLoading] = useState(false);
    const handleSubmit = async (e) => { e.preventDefault(); if (email === "admin@gmail.com") { setError("This email is reserved."); return; } setError(null); setIsLoading(true); try { await register(name, email, password, role); } catch (err) { setError(err.message); setIsLoading(false); } };
    return ( <PageWrapper><AuthCard title="Create your account"><form className="auth-form" onSubmit={handleSubmit}><div className="auth-form-inputs"><AnimatePresence><ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} /></AnimatePresence><Input id="name" name="name" type="text" placeholder="Full Name" value={name} onChange={(e) => setName(e.target.value)} /><Input id="email-address" name="email" type="email" autoComplete="email" placeholder="Email address" value={email} onChange={(e) => setEmail(e.target.value)} /><Input id="password" name="password" type="password" autoComplete="new-password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} /><Select id="role" name="role" value={role} onChange={(e) => setRole(e.target.value)}><option value="Receiver">I am a Receiver</option><option value="Donor">I am a Donor</option></Select></div><Button type="submit" isLoading={isLoading}><UserPlus className="button-icon" />Create Account</Button><div className="auth-form-footer"><Link to="/login">Already have an account? Sign in</Link></div></form></AuthCard></PageWrapper> );
}

// --- Shared UI Component: FormInput & FoodCard (No changes needed) ---
const FormInput = React.forwardRef(({ label, id, type = 'text', placeholder, value, onChange, required = false, min, ...props }, ref) => { const InputElement = type === 'textarea' ? 'textarea' : 'input'; return ( <div className="form-group"><label htmlFor={id} className="form-label">{label}</label><InputElement ref={ref} id={id} name={id} type={type} placeholder={placeholder} value={type !== 'file' ? value : undefined} onChange={type !== 'file' ? onChange : undefined} required={required} min={min} className={type === 'textarea' ? "form-textarea" : "form-input"} {...props} /></div> ); }); FormInput.displayName = 'FormInput';
function FoodCard({ listing, onDelete, onEdit, showDelete, showEdit, onClaim }) { const { user } = useAuth(); const isExpired = new Date(listing.expiryTime) < new Date(); const isFullyClaimed = listing.claims.length >= listing.maxClaims; const isClaimedByUser = user && listing.claims.some(claim => claim.userId.toString() === user._id.toString()); const remainingClaims = listing.maxClaims - listing.claims.length; return ( <motion.div className={`food-card ${isExpired ? 'card-expired' : ''} ${isFullyClaimed && !isExpired ? 'card-fully-claimed' : ''}`} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}> <div className="card-image-container"><img src={listing.imageUrl || 'https://placehold.co/600x400/a7a7a7/FFF?text=No+Image'} alt={listing.description} className="card-image" />{(isExpired || isFullyClaimed) && (<div className="card-status-overlay">{isExpired ? 'EXPIRED' : 'FULLY CLAIMED'}</div>)}</div><div className="card-content"><h3 className="card-title">{listing.description}</h3><div className="card-details"><p><Package className="detail-icon" /> Quantity: <strong>{listing.quantity}</strong></p><p><MapPin className="detail-icon" /> Location: <strong>{listing.location}</strong></p><p><CalendarDays className="detail-icon" /> Expiry: <strong>{new Date(listing.expiryTime).toLocaleString()}</strong></p><p><Users2 className="detail-icon" /> Slots: <strong>{remainingClaims} of {listing.maxClaims} remaining</strong></p>{onClaim && (<p className={isClaimedByUser ? 'claimed-status' : 'unclaimed-status'}>{isClaimedByUser ? (<><CheckCircle className="detail-icon" /> Claimed by you!</>) : ''}</p>)}{(showDelete || showEdit) && (<div className="card-claims-list"><p style={{marginTop:'0.5rem', fontWeight:'bold'}}>Claims ({listing.claims.length}):</p><ul>{listing.claims.map((claim, index) => (<li key={index}>{claim.name}</li>))}{listing.claims.length === 0 && <li>No claims.</li>}</ul></div>)}</div></div><div className="card-actions">{onClaim && (<Button onClick={onClaim} disabled={isExpired || isFullyClaimed || isClaimedByUser} className="button-claim">{isClaimedByUser ? 'Already Claimed' : (isFullyClaimed ? 'Fully Claimed' : 'Claim Food')}</Button>)}{(showEdit && onEdit) && (<Button onClick={onEdit} className="button-secondary button-edit-delete"><Edit3 /></Button>)}{(showDelete && onDelete) && (<Button onClick={onDelete} className="button-danger button-edit-delete"><Trash2 /></Button>)}</div></motion.div> ); }

// --- Donor Dashboard Components (Add/Edit) (No changes needed) ---
function AddFoodListingForm({ onListingCreated }) { const [description, setDescription] = useState(''); const [quantity, setQuantity] = useState(''); const [location, setLocation] = useState(''); const [mfgTime, setMfgTime] = useState(''); const [expiryTime, setExpiryTime] = useState(''); const [maxClaims, setMaxClaims] = useState(1); const imageRef = useRef(null); const [error, setError] = useState(null); const [success, setSuccess] = useState(null); const [isLoading, setIsLoading] = useState(false); const { formFetch } = useApi(); const handleSubmit = async (e) => { e.preventDefault(); if (maxClaims < 1) { setError("Max claims must be >= 1."); return; } setError(null); setSuccess(null); setIsLoading(true); const formData = new FormData(); formData.append('description', description); formData.append('quantity', quantity); formData.append('location', location); formData.append('mfgTime', mfgTime); formData.append('expiryTime', expiryTime); formData.append('maxClaims', maxClaims); if (imageRef.current && imageRef.current.files[0]) { formData.append('image', imageRef.current.files[0]); } try { await formFetch('/food', formData, 'POST'); setSuccess('Listing created!'); setDescription(''); setQuantity(''); setLocation(''); setMfgTime(''); setExpiryTime(''); setMaxClaims(1); if (imageRef.current) imageRef.current.value = null; onListingCreated(); } catch (err) { setError(err.message); } finally { setIsLoading(false); } }; return ( <motion.div className="add-food-form-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}><h2>Create New Listing</h2><form onSubmit={handleSubmit}><AnimatePresence><ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} /><SuccessMessage key="success-msg" message={success} onDismiss={() => setSuccess(null)} /></AnimatePresence><FormInput label="Description" id="description" type="text" placeholder="e.g., 10 vegetable curry meals" value={description} onChange={(e) => setDescription(e.target.value)} required={true} /><div className="form-group-grid"><FormInput label="Quantity" id="quantity" type="text" placeholder="e.g., 10 packets, 5 kg" value={quantity} onChange={(e) => setQuantity(e.target.value)} required={true} /><FormInput label="Maximum Claims" id="maxClaims" type="number" min="1" placeholder="1" value={maxClaims} onChange={(e) => setMaxClaims(parseInt(e.target.value, 10) || 1)} required={true} /></div><FormInput label="Pickup Location" id="location" type="text" placeholder="Full address" value={location} onChange={(e) => setLocation(e.target.value)} required={true} /><FormInput label="Image File" id="image" type="file" ref={imageRef} accept="image/*" required={false} /><div className="form-group-grid"><FormInput label="Manufacture Time" id="mfgTime" type="datetime-local" value={mfgTime} onChange={(e) => setMfgTime(e.target.value)} required={true} /><FormInput label="Expiry Time" id="expiryTime" type="datetime-local" value={expiryTime} onChange={(e) => setExpiryTime(e.target.value)} required={true} /></div><div style={{ marginTop: '1.5rem' }}><Button type="submit" isLoading={isLoading}><PlusCircle className="button-icon" />Add Listing</Button></div></form></motion.div> ); }
function EditFoodListingForm({ listing, onListingUpdated, onCancel }) { const formatDate = (d) => new Date(d).toISOString().slice(0, 16); const [description, setDescription] = useState(listing.description); const [quantity, setQuantity] = useState(listing.quantity); const [location, setLocation] = useState(listing.location); const [mfgTime, setMfgTime] = useState(formatDate(listing.mfgTime)); const [expiryTime, setExpiryTime] = useState(formatDate(listing.expiryTime)); const [maxClaims, setMaxClaims] = useState(listing.maxClaims); const imageRef = useRef(null); const [error, setError] = useState(null); const [success, setSuccess] = useState(null); const [isLoading, setIsLoading] = useState(false); const { formFetch } = useApi(); const handleSubmit = async (e) => { e.preventDefault(); if (maxClaims < 1) { setError("Max claims must be >= 1."); return; } setError(null); setSuccess(null); setIsLoading(true); const formData = new FormData(); formData.append('description', description); formData.append('quantity', quantity); formData.append('location', location); formData.append('mfgTime', mfgTime); formData.append('expiryTime', expiryTime); formData.append('maxClaims', maxClaims); if (imageRef.current && imageRef.current.files[0]) { formData.append('image', imageRef.current.files[0]); } try { const updated = await formFetch(`/food/${listing._id}`, formData, 'PUT'); setSuccess('Listing updated!'); onListingUpdated(updated); } catch (err) { setError(err.message); } finally { setIsLoading(false); } }; return ( <motion.div className="add-food-form-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}><h2>Edit Listing: {listing.description}</h2><form onSubmit={handleSubmit}><AnimatePresence><ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} /><SuccessMessage key="success-msg" message={success} onDismiss={() => setSuccess(null)} /></AnimatePresence><FormInput label="Description" id="description-edit" type="text" value={description} onChange={(e) => setDescription(e.target.value)} required={true} /><div className="form-group-grid"><FormInput label="Quantity" id="quantity-edit" type="text" value={quantity} onChange={(e) => setQuantity(e.target.value)} required={true} /><FormInput label="Maximum Claims" id="maxClaims-edit" type="number" min="1" value={maxClaims} onChange={(e) => setMaxClaims(parseInt(e.target.value, 10) || 1)} required={true} /></div><FormInput label="Pickup Location" id="location-edit" type="text" value={location} onChange={(e) => setLocation(e.target.value)} required={true} /><FormInput label="Image (Leave blank to keep current)" id="image-edit" type="file" ref={imageRef} accept="image/*" required={false} />{listing.imageUrl && !listing.imageUrl.includes('placehold.co') && <p style={{marginTop:'0.5rem', fontSize:'0.9rem', paddingLeft: '0.2rem'}}>Current: <a href={listing.imageUrl} target="_blank" rel="noopener noreferrer">View</a></p>}<div className="form-group-grid"><FormInput label="Manufacture Time" id="mfgTime-edit" type="datetime-local" value={mfgTime} onChange={(e) => setMfgTime(e.target.value)} required={true} /><FormInput label="Expiry Time" id="expiryTime-edit" type="datetime-local" value={expiryTime} onChange={(e) => setExpiryTime(e.target.value)} required={true} /></div><div style={{ marginTop: '1.5rem', display: 'flex', gap: '1rem' }}><Button type="submit" isLoading={isLoading} className="button-primary"><Edit3 className="button-icon" />Update</Button><Button type="button" onClick={onCancel} className="button-secondary">Cancel</Button></div></form></motion.div> ); }

// --- Donor Dashboard (No changes needed) ---
function DonorDashboard() { const [view, setView] = useState('view'); const [listingToEdit, setListingToEdit] = useState(null); const [myListings, setMyListings] = useState([]); const [isLoading, setIsLoading] = useState(true); const [error, setError] = useState(null); const [successMessage, setSuccessMessage] = useState(null); const { jsonFetch } = useApi(); const fetchMyListings = useCallback(async () => { setIsLoading(true); setError(null); try { const data = await jsonFetch('/food/donor/me'); setMyListings(data); } catch (err) { setError(err.message); } finally { setIsLoading(false); } }, [jsonFetch]); const handleListingCreatedOrUpdated = () => { setView('view'); setListingToEdit(null); fetchMyListings(); }; const handleDeleteListing = async (listingId) => { if (!window.confirm("Delete this listing?")) return; setError(null); setSuccessMessage(null); setIsLoading(true); try { await jsonFetch(`/food/${listingId}`, { method: 'DELETE' }); setSuccessMessage('Deleted!'); fetchMyListings(); } catch (err) { setError(err.message); } finally { setIsLoading(false); } }; useEffect(() => { fetchMyListings(); }, [fetchMyListings]); const renderContent = () => { if (view === 'add') { return (<AddFoodListingForm onListingCreated={() => { setSuccessMessage('Created!'); handleListingCreatedOrUpdated(); }} />); } if (view === 'edit' && listingToEdit) { return (<EditFoodListingForm listing={listingToEdit} onListingUpdated={(updated) => { setSuccessMessage('Updated!'); setMyListings(myListings.map(l => l._id === updated._id ? updated : l)); handleListingCreatedOrUpdated(); }} onCancel={() => setView('view')} />); } if (isLoading) return <LoadingSpinner />; return ( <> <div className="dashboard-actions"><Button onClick={() => setView('add')} className="button-success"><PlusCircle className="button-icon" /> Add New Listing</Button></div><AnimatePresence><ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} /><SuccessMessage key="success-msg" message={successMessage} onDismiss={() => setSuccessMessage(null)} /></AnimatePresence><h2 className="dashboard-title">My Listings</h2> {myListings.length === 0 ? (<div className="empty-state"><Package /><p>No listings yet. Start sharing!</p></div>) : (<div className="food-list-grid"><AnimatePresence>{myListings.map(listing => (<FoodCard key={listing._id} listing={listing} showDelete={true} showEdit={true} onDelete={() => handleDeleteListing(listing._id)} onEdit={() => { setListingToEdit(listing); setView('edit'); }} />))}</AnimatePresence></div>)} </> ); }; return ( <PageWrapper><h1 className="page-header"><HeartHandshake className="header-icon" /> Donor Dashboard</h1><div className="dashboard-container">{renderContent()}</div></PageWrapper> ); }

// --- Receiver Dashboard (No changes needed) ---
function ReceiverDashboard() { const { user } = useAuth(); const [allListings, setAllListings] = useState([]); const [isLoading, setIsLoading] = useState(true); const [error, setError] = useState(null); const [successMessage, setSuccessMessage] = useState(null); const { jsonFetch } = useApi(); const fetchAllListings = useCallback(async () => { setIsLoading(true); setError(null); try { const data = await jsonFetch('/food'); const available = user ? data.filter(l => l.donorId !== user._id) : data; setAllListings(available); } catch (err) { setError(err.message); } finally { setIsLoading(false); } }, [jsonFetch, user]); const handleClaimFood = async (listingId) => { setError(null); setSuccessMessage(null); const listing = allListings.find(l => l._id === listingId); if (!user || !listing || listing.claims.some(c => c.userId === user._id) || listing.claims.length >= listing.maxClaims) { setError("Cannot claim this listing."); return; } try { const data = await jsonFetch(`/food/${listingId}/claim`, { method: 'POST' }); setSuccessMessage('Claimed! Contact donor for pickup.'); setAllListings(prev => prev.map(l => l._id === listingId ? data : l)); } catch (err) { setError(err.message); } }; useEffect(() => { fetchAllListings(); }, [fetchAllListings]); if (isLoading) return <LoadingSpinner />; return ( <PageWrapper><h1 className="page-header"><List className="header-icon" /> Available Listings</h1><div className="dashboard-container"><AnimatePresence><ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} /><SuccessMessage key="success-msg" message={successMessage} onDismiss={() => setSuccessMessage(null)} /></AnimatePresence><p className="page-intro">Browse available donations. Claim a slot to arrange pickup!</p> {allListings.length === 0 && !error ? (<div className="empty-state"><Package /><p>No active listings available now. Check back soon!</p></div>) : (<div className="food-list-grid"><AnimatePresence>{allListings.map(listing => (<FoodCard key={listing._id} listing={listing} onClaim={() => handleClaimFood(listing._id)} />))}</AnimatePresence></div>)}</div></PageWrapper> ); }


// --- *** UPDATED Admin Dashboard Components *** ---

// StatCard (No changes)
function StatCard({ title, value, icon, className }) { return ( <motion.div className={`stat-card ${className}`} whileHover={{ scale: 1.02 }}><div className="stat-icon-container">{icon}</div><div className="stat-content"><p className="stat-value">{value}</p><h3 className="stat-title">{title}</h3></div></motion.div> ); }

// ListingListTable (No changes needed, used by AdminDashboard)
function ListingListTable({ listings, onDelete }) {
    return (
        <div className="admin-table-card">
             {/* Title and Download Button */}
             <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1.5rem 1.5rem 0 1.5rem' }}>
                <h3>Food Listings</h3>
                <Button
                    onClick={() => generatePDF(listings)} // Call PDF generation function
                    className="button-secondary"
                    disabled={listings.length === 0}
                    title="Download current list as PDF"
                >
                    <Download className="button-icon" /> PDF
                </Button>
            </div>
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
                        {listings.length === 0 && <tr><td colSpan="6" style={{ textAlign: 'center', padding: '2rem' }}>No listings found for the selected filter.</td></tr>}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// *** PDF Generation Function (Add this outside the AdminDashboard component) ***
const generatePDF = (listings) => {
    if (!listings || listings.length === 0) {
        alert("No data available to generate PDF.");
        return;
    }

    const doc = new jsPDF();
    const tableColumn = ["Description", "Donor", "Status", "Expires", "Claims"];
    const tableRows = [];

    // Title
    doc.setFontSize(18);
    doc.text("Food Listings Report", 14, 22);

    // Prepare data
    listings.forEach(listing => {
        const isExpired = new Date(listing.expiryTime) < new Date();
        const isFullyClaimed = listing.claims.length >= listing.maxClaims;
        const status = isExpired ? "Expired" : (isFullyClaimed ? "Full" : "Active");

        const listingData = [
            listing.description,
            listing.donorName || 'N/A',
            status,
            new Date(listing.expiryTime).toLocaleString(),
            `${listing.claims.length}/${listing.maxClaims}`
        ];
        tableRows.push(listingData);
    });

    // Add table using autoTable
    doc.autoTable({
        head: [tableColumn],
        body: tableRows,
        startY: 30, // Start table below the title
        theme: 'grid', // or 'striped' or 'plain'
        styles: { fontSize: 8 },
        headStyles: { fillColor: [79, 70, 229] }, // Header color (primary)
    });

    // Add date generated
    const date = new Date().toLocaleDateString();
    doc.setFontSize(10);
    doc.text(`Generated on: ${date}`, 14, doc.lastAutoTable.finalY + 10);

    // Save the PDF
    doc.save(`food_listings_report_${date}.pdf`);
};


// --- *** UPDATED AdminDashboard Component *** ---
function AdminDashboard() {
    // REMOVED: users state and related logic
    const [stats, setStats] = useState({
        totalUsers: 0, // Keep stats structure consistent even if not all displayed
        totalDonors: 0,
        totalListings: 0,
        activeListings: 0
    });
    const [listings, setListings] = useState([]); // Only listings state needed
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [successMessage, setSuccessMessage] = useState(null);
    const [filter, setFilter] = useState(''); // State for filter dropdown
    const { jsonFetch } = useApi();

    // Fetch only stats and filtered listings
    const fetchData = useCallback(async () => {
        setIsLoading(true);
        setError(null);
        const filterQuery = filter ? `?filter=${filter}` : '';

        try {
            // Fetch in parallel
            const [statsData, listingsData] = await Promise.all([
                jsonFetch(`/admin/dashboard${filterQuery}`),
                jsonFetch(`/admin/food${filterQuery}`) // Fetch filtered listings
            ]);

            setStats(statsData);
            setListings(listingsData);

        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    }, [jsonFetch, filter]); // Depend on filter

    // Delete listing function (no changes needed)
    const handleDeleteListing = async (listingId) => {
        if (!window.confirm("Admin: Delete this listing?")) return;
        setError(null); setSuccessMessage(null);
        try {
            await jsonFetch(`/admin/food/${listingId}`, { method: 'DELETE' });
            setSuccessMessage('Listing deleted by Admin.');
            setListings(prev => prev.filter(l => l._id !== listingId));
        } catch (err) { setError(err.message); }
    };

    // Fetch data on initial load and when filter changes
    useEffect(() => {
        fetchData();
    }, [fetchData]);

    if (isLoading) return <LoadingSpinner />;

    return (
        <PageWrapper>
            <h1 className="page-header"><LayoutDashboard className="header-icon" /> Admin Dashboard</h1>
            <div className="dashboard-container admin-dashboard">
                <AnimatePresence>
                    <ErrorMessage key="error-msg" message={error} onDismiss={() => setError(null)} />
                    <SuccessMessage key="success-msg" message={successMessage} onDismiss={() => setSuccessMessage(null)} />
                </AnimatePresence>

                 {/* Filter UI */}
                 <div className="admin-filter-bar">
                    <label htmlFor="admin-filter" className="form-label">Filter Listings By Creation Date:</label>
                    <select
                        id="admin-filter"
                        className="form-select"
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        style={{ maxWidth: '250px' }}
                    >
                        <option value="">All Time</option>
                        <option value="1week">Last 7 Days</option>
                        <option value="1month">Last 30 Days</option>
                        {/* <option value="6month">Last 6 Months</option>  Backend doesn't support 6 months currently */}
                        <option value="1year">Last 1 Year</option>
                    </select>
                </div>

                {/* Stat Cards - Still show overall stats (optional) */}
                {/* You can remove stats if you don't need them */}
                 <div className="admin-stats-grid">
                    <StatCard title="Total Users" value={stats.totalUsers} icon={<Users />} className="stat-users" />
                    <StatCard title="Total Donors" value={stats.totalDonors} icon={<HeartHandshake />} className="stat-donors" />
                    <StatCard title="Total Listings (Filtered)" value={listings.length} icon={<Package />} className="stat-listings" />
                    <StatCard title="Active Listings (Overall)" value={stats.activeListings} icon={<CheckCircle />} className="stat-active" />
                 </div>


                {/* REMOVED: UserListTable */}
                {/* Listings Table with Download Button added inside */}
                <div className="admin-tables-container">
                    {/* UserListTable removed */}
                    <ListingListTable listings={listings} onDelete={handleDeleteListing} />
                </div>
            </div>
        </PageWrapper>
    );
}
