import React, {
  useState,
  useEffect,
  createContext,
  useContext,
  useMemo,
} from 'react';
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
  ClipboardList // Icon for claims button
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
  const [currentPage, setCurrentPage] = useState('login');

  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    const storedUser = localStorage.getItem('user');

    if (storedToken && storedUser) {
      try {
        const parsedUser = JSON.parse(storedUser);
        setToken(storedToken);
        setUser(parsedUser);
        setRole(parsedUser.role);
        redirectToDashboard(parsedUser.role);
      } catch (e) {
        console.error("Failed to parse stored user:", e);
        logout();
      }
    } else {
      setCurrentPage('login');
    }
    setIsLoading(false);
  }, []);

  // *** UPDATED: AdminDashboard link is RESTORED ***
  const redirectToDashboard = (userRole) => {
    if (userRole === 'Admin') setCurrentPage('adminDashboard');
    else if (userRole === 'Donor') setCurrentPage('donorDashboard');
    else if (userRole === 'Receiver') setCurrentPage('receiverDashboard');
    else setCurrentPage('login');
  };

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

  const login = async (email, password) => {
    const { token, user } = await apiLogin(email, password);
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    setToken(token);
    setUser(user);
    setRole(user.role);
    redirectToDashboard(user.role);
  };

  const register = async (name, email, password, role) => {
    const { token, user } = await apiRegister(name, email, password, role);
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    setToken(token);
    setUser(user);
    setRole(user.role);
    redirectToDashboard(user.role);
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('role');
    setToken(null);
    setUser(null);
    setRole(null);
    setCurrentPage('login');
  };

  const value = useMemo(
    () => ({
      user, token, role, isLoggedIn: !!token, isLoading,
      login, logout, register,
      currentPage, setCurrentPage,
    }), [user, token, role, isLoading, currentPage]
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
  return (
    <AuthProvider>
      <Header />
      <main>
        <AnimatePresence mode="wait">
          <PageContent />
        </AnimatePresence>
      </main>
    </AuthProvider>
  );
}

// --- Page-Switching Component (*** UPDATED ***) ---
function PageContent() {
  const { currentPage, isLoggedIn } = useAuth();
  switch (currentPage) {
    case 'login': return <LoginPage key="login" />;
    case 'register': return <RegisterPage key="register" />;
    case 'donorDashboard': return isLoggedIn ? <DonorDashboard key="donor" /> : <LoginPage key="login" />;
    case 'receiverDashboard': return isLoggedIn ? <ReceiverDashboard key="receiver" /> : <LoginPage key="login" />;
    // *** RESTORED: AdminDashboard case ***
    case 'adminDashboard': return isLoggedIn ? <AdminDashboard key="admin" /> : <LoginPage key="login" />;
    default: return <LoginPage key="login" />;
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

const Select = React.forwardRef(({ id, name, children, ...props }, ref) => (
  <div>
    <label htmlFor={id} className="sr-only">{name}</label>
    <select ref={ref} id={id} name={name} required className="form-select" {...props}>
      {children}
    </select>
  </div>
));

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

// --- Header (*** UPDATED ***) ---
function Header() {
  const { isLoggedIn, role, logout, setCurrentPage, user } = useAuth();
  return (
    <nav className="header-nav">
      <div className="header-container">
        <div className="header-logo">
          <UtensilsCrossed className="header-logo-icon" />
          <span className="header-logo-text">LeftoverLink</span>
        </div>
        <div className="header-links">
          {isLoggedIn ? (
            <>
              {/* Show (Admin) text if admin */}
              <span className="header-user-greeting">Hi, <span>{user?.name}</span> {role === 'Admin' && '(Admin)'}</span>
              <HeaderButton
                onClick={() => {
                  // *** UPDATED: Logic restored ***
                  if (role === 'Admin') setCurrentPage('adminDashboard');
                  if (role === 'Donor') setCurrentPage('donorDashboard');
                  if (role === 'Receiver') setCurrentPage('receiverDashboard');
                }}
                icon={<LayoutDashboard className="header-button-icon" />}
              >
                Dashboard
              </HeaderButton>
              <HeaderButton onClick={logout} icon={<LogOut className="header-button-icon" />} className="logout">
                Logout
              </HeaderButton>
            </>
          ) : (
            <>
              <HeaderButton onClick={() => setCurrentPage('login')} icon={<LogIn className="header-button-icon" />}>
                Login
              </HeaderButton>
              <HeaderButton onClick={() => setCurrentPage('register')} icon={<UserPlus className="header-button-icon" />} className="register">
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

// --- API Helper Hook ---
function useApi() {
  const { token, logout } = useAuth();
  const authenticatedFetch = async (endpoint, options = {}) => {
    const headers = { 'Content-Type': 'application/json', ...options.headers };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const response = await fetch(`${BACKEND_URL}${endpoint}`, { ...options, headers });
    if (response.status === 401) {
      logout();
      throw new Error('Your session has expired. Please log in again.');
    }
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || 'An API error occurred');
    }
    return data;
  };
  return authenticatedFetch;
}

// --- 1. Login Page (*** UPDATED ***) ---
function LoginPage() {
  const { login, setCurrentPage } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isAdminLoading, setIsAdminLoading] = useState(false); // *** NEW ***

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      await login(email, password);
    } catch (err) {
      setError(err.message);
      setIsLoading(false);
    }
  };
  
  // *** NEW: Handler for the Admin Login button ***
  const handleAdminLogin = async () => {
    setError(null);
    setIsAdminLoading(true);
    try {
      // Hardcoded credentials as requested
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
            <ErrorMessage message={error} onDismiss={() => setError(null)} />
            <Input id="email-address" name="email" type="email" autoComplete="email" placeholder="Email address" value={email} onChange={(e) => setEmail(e.target.value)} />
            <Input id="password" name="password" type="password" autoComplete="current-password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <Button type="submit" isLoading={isLoading}><LogIn className="button-icon" />Sign in</Button>
          <div className="auth-form-footer">
            <button type="button" onClick={() => setCurrentPage('register')}>Need an account? Register</button>
          </div>
          
          {/* --- *** NEW: Admin Login Button *** --- */}
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

// --- 2. Register Page ---
function RegisterPage() {
  const { register, setCurrentPage } = useAuth();
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
            <ErrorMessage message={error} onDismiss={() => setError(null)} />
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
            <button type="button" onClick={() => setCurrentPage('login')}>Already have an account? Sign in</button>
          </div>
        </form>
      </AuthCard>
    </PageWrapper>
  );
}

// --- 3. Donor Dashboard ---
function DonorDashboard() {
  const [view, setView] = useState('view'); // 'view' or 'add'
  const [myListings, setMyListings] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const api = useApi();

  const fetchMyListings = async () => {
    setIsLoading(true);
    try {
      const data = await api('/food/mylistings');
      setMyListings(data);
    } catch (err) {
      setError(err.message);
    }
    setIsLoading(false);
  };

  useEffect(() => { fetchMyListings(); }, []);

  const handleListingCreated = (newListing) => {
    setMyListings([newListing, ...myListings]);
    setView('view');
  };

  const deleteListing = async (id) => {
    try {
      await api(`/food/${id}`, { method: 'DELETE' });
      setMyListings(myListings.filter(l => l._id !== id));
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <PageWrapper>
      <div className="page-header">
        <h1 className="page-title">Donor Dashboard</h1>
        <motion.button onClick={() => setView(view === 'view' ? 'add' : 'view')} className="button page-header-button" whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
          {view === 'view' ? (<><PlusCircle className="button-icon" /><span>Add New Listing</span></>) : (<><List className="button-icon" /><span>View My Listings</span></>)}
        </motion.button>
      </div>
      <AnimatePresence mode="wait">
        {view === 'add' ? (
          <motion.div key="add" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <AddFoodListingForm onListingCreated={handleListingCreated} />
          </motion.div>
        ) : (
          <motion.div key="view" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '1rem' }}>My Listings</h2>
            <ErrorMessage message={error} onDismiss={() => setError(null)} />
            {isLoading ? <LoadingSpinner /> : myListings.length === 0 ? (
              <p className="no-items-message">You have not created any listings yet.</p>
            ) : (
              <div className="card-grid">
                {myListings.map(listing => (
                  <FoodCard key={listing._id} listing={listing} onDelete={() => deleteListing(listing._id)} showDelete={true} />
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </PageWrapper>
  );
}

// --- Component: Add Food Listing Form ---
function AddFoodListingForm({ onListingCreated }) {
  const [description, setDescription] = useState('');
  const [quantity, setQuantity] = useState('');
  const [location, setLocation] = useState('');
  const [imageUrl, setImageUrl] = useState('');
  const [mfgTime, setMfgTime] = useState('');
  const [expiryTime, setExpiryTime] = useState('');
  const [maxClaims, setMaxClaims] = useState(1);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const api = useApi();

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (maxClaims < 1) {
      setError("Maximum claims must be 1 or more.");
      return;
    }
    setError(null);
    setSuccess(null);
    setIsLoading(true);
    try {
      const newListing = { description, quantity, location, imageUrl, mfgTime, expiryTime, maxClaims };
      const savedListing = await api('/food', { method: 'POST', body: JSON.stringify(newListing) });
      setSuccess('Listing created successfully!');
      setIsLoading(false);
      setDescription(''); setQuantity(''); setLocation(''); setImageUrl(''); setMfgTime(''); setExpiryTime(''); setMaxClaims(1);
      onListingCreated(savedListing);
    } catch (err) {
      setError(err.message);
      setIsLoading(false);
    }
  };

  return (
    <motion.div className="add-food-form-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
      <h2>Create New Food Listing</h2>
      <form onSubmit={handleSubmit}>
        <ErrorMessage message={error} onDismiss={() => setError(null)} />
        <SuccessMessage message={success} onDismiss={() => setSuccess(null)} />
        <FormInput label="Description" id="description" type="text" placeholder="e.g., 10 vegetable curry meals" value={description} onChange={(e) => setDescription(e.target.value)} />
        <div className="form-group-grid">
          <FormInput label="Quantity" id="quantity" type="text" placeholder="e.g., 10 packets, 5 kg" value={quantity} onChange={(e) => setQuantity(e.target.value)} />
          <FormInput label="Maximum Claims" id="maxClaims" type="number" min="1" placeholder="1" value={maxClaims} onChange={(e) => setMaxClaims(parseInt(e.target.value, 10) || 1)} />
        </div>
        <FormInput label="Pickup Location" id="location" type="text" placeholder="Full address" value={location} onChange={(e) => setLocation(e.target.value)} />
        <FormInput label="Image URL (Optional)" id="imageUrl" type="text" placeholder="https://your-image-url.com/food.jpg" value={imageUrl} onChange={(e) => setImageUrl(e.target.value)} />
        <div className="form-group-grid">
          <FormInput label="Manufacture Time" id="mfgTime" type="datetime-local" value={mfgTime} onChange={(e) => setMfgTime(e.target.value)} />
          <FormInput label="Expiry Time" id="expiryTime" type="datetime-local" value={expiryTime} onChange={(e) => setExpiryTime(e.target.value)} />
        </div>
        <div style={{ marginTop: '1.5rem' }}>
          <Button type="submit" isLoading={isLoading}><PlusCircle className="button-icon" />Add Listing</Button>
        </div>
      </form>
    </motion.div>
  );
}

function FormInput({ label, id, ...props }) {
  return (
    <div className="form-group">
      <label htmlFor={id}>{label}</label>
      <input id={id} required className="form-input" {...props} />
    </div>
  );
}

// --- 4. Receiver Dashboard (*** UPDATED ***) ---
function ReceiverDashboard() {
  const [view, setView] = useState('all'); // 'all' or 'claims'
  const [listings, setListings] = useState([]);
  const [myClaims, setMyClaims] = useState([]); // *** NEW ***
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const api = useApi();

  const fetchListings = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api('/food');
      setListings(data);
    } catch (err) {
      setError(err.message);
    }
    setIsLoading(false);
  };

  const fetchMyClaims = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api('/food/myclaims');
      setMyClaims(data);
    } catch (err) {
      setError(err.message);
    }
    setIsLoading(false);
  };

  useEffect(() => {
    if (view === 'all') {
      fetchListings();
    } else if (view === 'claims') {
      fetchMyClaims();
    }
  }, [view]);

  const handleClaim = async (id) => {
    setError(null);
    setSuccess(null);
    try {
      const { message, listing: updatedListing } = await api(`/food/${id}/claim`, { method: 'PUT' });
      setSuccess(message);
      const isNowFull = updatedListing.claims.length >= updatedListing.maxClaims;
      if (isNowFull) {
        setListings(listings.filter(l => l._id !== id));
      } else {
        setListings(listings.map(l => l._id === id ? updatedListing : l));
      }
    } catch (err) {
      setError(err.message);
    }
  };
  
  const listToDisplay = view === 'all' ? listings : myClaims;
  const pageTitle = view === 'all' ? 'Available Food' : 'My Claimed Food';
  const noItemsMessage = view === 'all' 
    ? "No available food listings at the moment. Please check back later."
    : "You have not claimed any food items yet.";

  return (
    <PageWrapper>
      <div className="page-header">
        <h1 className="page-title">{pageTitle}</h1>
        {/* --- *** NEW: Toggle Button *** --- */}
        <motion.button 
          onClick={() => setView(view === 'all' ? 'claims' : 'all')} 
          className="button page-toggle-button" 
          whileHover={{ scale: 1.05 }} 
          whileTap={{ scale: 0.95 }}
        >
          {view === 'all' ? (
            <><ClipboardList className="button-icon" /><span>Show My Claims</span></>
          ) : (
            <><List className="button-icon" /><span>Show All Available</span></>
          )}
        </motion.button>
      </div>
      
      <ErrorMessage message={error} onDismiss={() => setError(null)} />
      <SuccessMessage message={success} onDismiss={() => setSuccess(null)} />
      
      {isLoading ? <LoadingSpinner /> : listToDisplay.length === 0 ? (
        <p className="no-items-message">{noItemsMessage}</p>
      ) : (
        <motion.div
          className="card-grid"
          variants={{ hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.1 } } }}
          initial="hidden"
          animate="show"
        >
          {listToDisplay.map(listing => (
            <FoodCard 
              key={listing._id} 
              listing={listing} 
              onClaim={() => handleClaim(listing._id)} 
              showClaim={view === 'all'} 
            />
          ))}
        </motion.div>
      )}
    </PageWrapper>
  );
}

// --- Component: Food Card (*** UPDATED ***) ---
function FoodCard({ listing, onClaim, showClaim, onDelete, showDelete }) {
  const { user } = useAuth(); 
  
  const {
    _id, description, quantity, location, imageUrl, mfgTime, expiryTime, donorName,
    claims = [],
    maxClaims = 1
  } = listing;

  const mfgDate = new Date(mfgTime).toLocaleString();
  const expiryDate = new Date(expiryTime).toLocaleString();
  const isExpired = new Date(expiryTime) < new Date();
  
  const totalClaims = claims.length;
  const isAvailable = totalClaims < maxClaims && !isExpired;
  const remainingClaims = maxClaims - totalClaims;
  const hasUserClaimed = claims.some(claim => claim.userId === user._id);

  return (
    <motion.div
      className={`food-card ${isExpired ? 'food-card-expired' : ''}`}
      variants={{ hidden: { y: 20, opacity: 0 }, show: { y: 0, opacity: 1 } }}
      whileHover={{ scale: 1.03, transition: { duration: 0.2 } }}
    >
      <img className="food-card-image" src={imageUrl} alt={description} onError={(e) => { e.target.src = 'https://placehold.co/600x400/a7a7a7/FFF?text=Image+Error'; }} />
      <div className="food-card-content">
        <span className={`food-card-status ${isAvailable ? 'food-card-status-available' : 'food-card-status-claimed'}`}>
          {isExpired ? 'Expired' : (isAvailable ? 'Available' : 'Fully Claimed')}
        </span>
        
        <h3 className="food-card-title">{description}</h3>
        <p className="food-card-quantity">{quantity}</p>

        <div className="food-card-details">
          <div className="food-card-detail-item"><UserPlus className="icon" /><span>Donated by: <span className="label">{donorName}</span></span></div>
          <div className="food-card-detail-item"><MapPin className="icon" /><span>{location}</span></div>
          <div className="food-card-detail-item"><CalendarDays className="icon" /><span>Prepared: {mfgDate}</span></div>
          <div className={`food-card-detail-item ${isExpired ? 'food-card-detail-expired' : ''}`}><Clock className="icon" /><span>Use by: {expiryDate}</span></div>
          
          <div className="food-card-detail-item">
            <Users2 className="icon" />
            <span>Slots: <span className="label">{totalClaims} / {maxClaims} Claimed</span></span>
          </div>
        </div>

        {/* --- *** NEW: Show list of claimants (for Donor) *** --- */}
        {showDelete && totalClaims > 0 && (
          <div className="food-card-claims-list">
            <h4>Claimed By:</h4>
            <ul>
              {claims.map((claim) => (
                <li key={claim.userId}>{claim.name}</li>
              ))}
            </ul>
          </div>
        )}
        
        {/* Show "Claimed" for items user has claimed (in Receiver's "My Claims" view) */}
        {!showClaim && !showDelete && hasUserClaimed && (
          <Button disabled={true}>
            <CheckCircle className="button-icon" />
            You Claimed This
          </Button>
        )}

        {/* Updated Button Logic (for Receiver's "Available" view) */}
        {showClaim && isAvailable && (
          <Button onClick={() => onClaim(_id)} disabled={hasUserClaimed}>
            <CheckCircle className="button-icon" />
            {hasUserClaimed ? 'Already Claimed' : `Claim ( ${remainingClaims} left )`}
          </Button>
        )}
        
        {/* Delete Button (for Donor) */}
        {showDelete && (
          <Button onClick={() => onDelete(_id)} className="button-danger" style={{marginTop: '0.5rem'}}>
            <Trash2 className="button-icon" />
            Delete Listing
          </Button>
        )}
      </div>
    </motion.div>
  );
}


// --- *** 5. Admin Dashboard (RESTORED) *** ---
function AdminDashboard() {
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [listings, setListings] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const api = useApi();

  const fetchData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [statsData, usersData, listingsData] = await Promise.all([
        api(`/admin/dashboard?filter=${filter}`),
        api('/admin/users'),
        api(`/admin/listings?filter=${filter}`),
      ]);
      setStats(statsData);
      setUsers(usersData);
      setListings(listingsData);
    } catch (err) {
      setError(err.message);
    }
    setIsLoading(false);
  };

  useEffect(() => { fetchData(); }, [filter]);
  
  // Admin can delete any listing
  const deleteListing = async (id) => {
    try {
      await api(`/food/${id}`, { method: 'DELETE' });
      // Refetch data to ensure lists are consistent
      fetchData(); 
    } catch (err) {
      setError(err.message);
    }
  };

  const filterOptions = [
    { label: 'All Time', value: 'all' },
    { label: 'Last 1 Week', value: '1week' },
    { label: 'Last 1 Month', value: '1month' },
    { label: 'Last 3 Months', value: '3month' },
    { label: 'Last 1 Year', value: '1year' },
  ];

  return (
    <PageWrapper>
      <h1 className="page-title" style={{ marginBottom: '1.5rem' }}>Admin Dashboard</h1>
      <ErrorMessage message={error} onDismiss={() => setError(null)} />
      
      <div className="admin-filter-buttons">
        {filterOptions.map(option => (
          <FilterButton key={option.value} label={option.label} onClick={() => setFilter(option.value)} active={filter === option.value} />
        ))}
      </div>
      
      <div className="admin-stats-grid">
        <StatCard title="Total Users" value={stats?.users.total} icon={<Users className="admin-stat-card-icon admin-stat-card-icon-blue" />} isLoading={isLoading} />
        <StatCard title="Total Listings" value={stats?.listings.total} icon={<Package className="admin-stat-card-icon admin-stat-card-icon-green" />} isLoading={isLoading} />
        <StatCard title="Available Listings" value={stats?.listings.available} icon={<CheckCircle className="admin-stat-card-icon admin-stat-card-icon-indigo" />} isLoading={isLoading} />
      </div>

      <div className="admin-data-grid">
        <div className="admin-data-card">
          <h2>Manage Users ({users.length})</h2>
          <div className="admin-table-wrapper">
            {isLoading ? <LoadingSpinner /> : (
              <table className="admin-table">
                <thead><tr><th>Name</th><th>Email</th><th>Role</th></tr></thead>
                <tbody>
                  {users.map(user => (
                    <tr key={user._id}>
                      <td className="text-medium">{user.name}</td>
                      <td className="text-light">{user.email}</td>
                      <td><span className={`status-badge ${user.role === 'Admin' ? 'status-admin' : user.role === 'Donor' ? 'status-donor' : 'status-receiver'}`}>{user.role}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div className="admin-data-card">
          <h2>Manage Listings ({listings.length} found)</h2>
           <div className="admin-table-wrapper">
            {isLoading ? <LoadingSpinner /> : (
              <table className="admin-table">
                <thead><tr><th>Description</th><th>Donor</th><th>Status (Claims)</th><th>Created</th><th>Action</th></tr></thead>
                <tbody>
                  {listings.map(listing => {
                    const totalClaims = listing.claims?.length || 0;
                    const maxClaims = listing.maxClaims || 1;
                    const isAvailable = totalClaims < maxClaims && new Date(listing.expiryTime) > new Date();
                    return (
                      <tr key={listing._id}>
                        <td className="text-medium">{listing.description}</td>
                        <td className="text-light">{listing.donorName}</td>
                        <td>
                          <span className={`status-badge ${isAvailable ? 'status-available' : 'status-claimed'}`}>
                            {isAvailable ? 'Available' : 'Full/Expired'} ({totalClaims}/{maxClaims})
                          </span>
                        </td>
                        <td className="text-light">{new Date(listing.createdAt).toLocaleDateString()}</td>
                        <td>
                          <button onClick={() => deleteListing(listing._id)} className="action-button">
                            <Trash2 className="icon" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </PageWrapper>
  );
}

function FilterButton({ label, onClick, active }) {
  return (
    <button
      onClick={onClick}
      className={`filter-button ${active ? 'active' : ''}`}
    >
      {label}
    </button>
  );
}

function StatCard({ title, value, icon, isLoading }) {
  return (
    <motion.div className="admin-stat-card" whileHover={{ scale: 1.05 }}>
      <div>
        <p className="admin-stat-card-title">{title}</p>
        <p className="admin-stat-card-value">
          {isLoading ? <Loader2 className="spinner-inline" /> : (value !== undefined ? value : 0)}
        </p>
      </div>
      <div className="admin-stat-card-icon-wrapper">{icon}</div>
    </motion.div>
  );
}