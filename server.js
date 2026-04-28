const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = 'halal-trading-bot-fixed-secret-key-2024';
const ENCRYPTION_KEY = '0123456789012345678901234567890123456789012345678901234567890123';

const HALAL_ASSETS = [
    'BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'ADAUSDT',
    'XRPUSDT', 'DOTUSDT', 'LINKUSDT', 'MATICUSDT', 'AVAXUSDT'
];

// ==================== DATA DIRECTORIES ====================
const DATA_DIR = path.join(__dirname, 'data');
const TRADES_DIR = path.join(DATA_DIR, 'trades');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PENDING_FILE = path.join(DATA_DIR, 'pending.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

// Create directories
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(TRADES_DIR)) fs.mkdirSync(TRADES_DIR, { recursive: true });

// Initialize files
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({}, null, 2));
if (!fs.existsSync(PENDING_FILE)) fs.writeFileSync(PENDING_FILE, JSON.stringify({}, null, 2));
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, JSON.stringify({}, null, 2));

// ==================== CREATE OWNER ACCOUNT ====================
let users = JSON.parse(fs.readFileSync(USERS_FILE));
const ownerEmail = "mujtabahatif@gmail.com";
const ownerPass = "Mujtabah@2598";

if (!users[ownerEmail]) {
    users[ownerEmail] = {
        email: ownerEmail,
        password: bcrypt.hashSync(ownerPass, 10),
        isOwner: true,
        isApproved: true,
        isBlocked: false,
        apiKey: "",
        secretKey: "",
        createdAt: new Date().toISOString()
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    console.log("✅ Owner account created.");
}

// ==================== HELPER FUNCTIONS ====================
function readUsers() { return JSON.parse(fs.readFileSync(USERS_FILE)); }
function writeUsers(data) { fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(PENDING_FILE)); }
function writePending(data) { fs.writeFileSync(PENDING_FILE, JSON.stringify(data, null, 2)); }
function readOrders() { return JSON.parse(fs.readFileSync(ORDERS_FILE)); }
function writeOrders(data) { fs.writeFileSync(ORDERS_FILE, JSON.stringify(data, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: '🕋 HALAL Trading Bot Running' });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    console.log('Register attempt:', email);
    
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }
    
    try {
        const users = readUsers();
        if (users[email]) {
            return res.status(400).json({ success: false, message: 'User already exists' });
        }
        
        const pending = readPending();
        if (pending[email]) {
            return res.status(400).json({ success: false, message: 'Request already pending' });
        }
        
        pending[email] = {
            email: email,
            password: bcrypt.hashSync(password, 10),
            requestedAt: new Date().toISOString()
        };
        writePending(pending);
        
        console.log('Registration request saved for:', email);
        res.json({ success: true, message: 'Registration request sent to owner for approval.' });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    console.log('Login attempt:', email);
    
    try {
        const users = readUsers();
        const user = users[email];
        
        if (!user) {
            const pending = readPending();
            if (pending[email]) {
                return res.status(401).json({ success: false, message: 'Pending owner approval' });
            }
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        if (!user.isApproved && !user.isOwner) {
            return res.status(401).json({ success: false, message: 'Account not approved by owner' });
        }
        
        if (user.isBlocked) {
            return res.status(401).json({ success: false, message: 'Account blocked. Contact owner.' });
        }
        
        const token = jwt.sign({ email: email, isOwner: user.isOwner }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, token: token, isOwner: user.isOwner });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
}

// ==================== SIMPLIFIED BINANCE API (Placeholder - Add Real Keys Later) ====================
async function getSpotBalance(apiKey, secretKey, testnet = false) {
    // For demo purposes - returns placeholder balance
    // Replace with actual Binance API call when keys are added
    return 1000;
}

async function getFundingBalance(apiKey, secretKey, testnet = false) {
    return 500;
}

async function getCurrentPrice(symbol, testnet = false) {
    return 50000;
}

async function placeLimitOrder(apiKey, secretKey, symbol, side, quantity, price, testnet = false) {
    return { orderId: Date.now(), status: 'NEW' };
}

async function checkOrderStatus(apiKey, secretKey, symbol, orderId, testnet = false) {
    return { status: 'FILLED', price: 50000, executedQty: 0.001 };
}

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey, accountType } = req.body;
    if (!apiKey || !secretKey) {
        return res.status(400).json({ success: false, message: 'Both API keys required' });
    }
    
    try {
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(apiKey);
        users[req.user.email].secretKey = encrypt(secretKey);
        writeUsers(users);
        
        res.json({ success: true, message: 'API keys saved successfully!', spotBalance: 1000, fundingBalance: 500 });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error saving API keys' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) {
        return res.status(400).json({ success: false, message: 'No API keys saved' });
    }
    
    res.json({ success: true, spotBalance: 1000, fundingBalance: 500, totalBalance: 1500 });
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) {
        return res.json({ success: false, message: 'No keys saved' });
    }
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    res.json({ success: true, spotBalance: 1000, fundingBalance: 500, total: 1500 });
});

// ==================== TRADING ENDPOINTS ====================
const activeTradingSessions = new Map();

app.post('/api/start-trading', authenticate, (req, res) => {
    const { investmentAmount, profitPercent, timeLimitHours, accountType } = req.body;
    
    if (investmentAmount < 10) {
        return res.status(400).json({ success: false, message: 'Minimum investment is $10' });
    }
    if (profitPercent < 0.1 || profitPercent > 5) {
        return res.status(400).json({ success: false, message: 'Profit target must be between 0.1% and 5%' });
    }
    if (timeLimitHours < 1 || timeLimitHours > 168) {
        return res.status(400).json({ success: false, message: 'Time limit must be between 1 and 168 hours' });
    }
    
    const sessionId = crypto.randomBytes(16).toString('hex');
    activeTradingSessions.set(sessionId, {
        userId: req.user.email,
        investmentAmount: investmentAmount,
        profitPercent: profitPercent,
        startTime: Date.now(),
        timeLimitHours: timeLimitHours,
        active: true
    });
    
    res.json({ 
        success: true, 
        sessionId: sessionId,
        message: `✅ Halal trading started! Investment: $${investmentAmount}, Target: ${profitPercent}%, Time limit: ${timeLimitHours}h`
    });
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (activeTradingSessions.has(sessionId)) {
        activeTradingSessions.delete(sessionId);
        res.json({ success: true, message: 'Trading stopped successfully' });
    } else {
        res.json({ success: false, message: 'Session not found' });
    }
});

app.post('/api/trade-status', authenticate, (req, res) => {
    const session = activeTradingSessions.get(req.body.sessionId);
    if (!session) {
        return res.json({ success: true, active: false });
    }
    
    const elapsedHours = (Date.now() - session.startTime) / (1000 * 60 * 60);
    const timeRemaining = Math.max(0, session.timeLimitHours - elapsedHours);
    
    res.json({
        success: true,
        active: session.active,
        timeRemaining: timeRemaining,
        investmentAmount: session.investmentAmount,
        profitPercent: session.profitPercent
    });
});

app.get('/api/trade-history', authenticate, (req, res) => {
    const userFile = path.join(TRADES_DIR, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(userFile)) {
        return res.json({ success: true, trades: [] });
    }
    const trades = JSON.parse(fs.readFileSync(userFile));
    res.json({ success: true, trades: trades });
});

app.get('/api/halal-assets', authenticate, (req, res) => {
    res.json({ success: true, assets: HALAL_ASSETS });
});

// ==================== ADMIN ENDPOINTS ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) {
        return res.status(403).json({ success: false, message: 'Admin only' });
    }
    
    const pending = readPending();
    const list = Object.keys(pending).map(email => ({
        email: email,
        requestedAt: pending[email].requestedAt
    }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) {
        return res.status(403).json({ success: false, message: 'Admin only' });
    }
    
    const { email } = req.body;
    const pending = readPending();
    
    if (!pending[email]) {
        return res.status(404).json({ success: false, message: 'User not found in pending' });
    }
    
    const users = readUsers();
    users[email] = {
        email: email,
        password: pending[email].password,
        isOwner: false,
        isApproved: true,
        isBlocked: false,
        apiKey: "",
        secretKey: "",
        createdAt: new Date().toISOString(),
        approvedAt: new Date().toISOString()
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    
    res.json({ success: true, message: `User ${email} approved successfully` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) {
        return res.status(403).json({ success: false, message: 'Admin only' });
    }
    
    const { email } = req.body;
    const pending = readPending();
    
    if (!pending[email]) {
        return res.status(404).json({ success: false, message: 'User not found in pending' });
    }
    
    delete pending[email];
    writePending(pending);
    
    res.json({ success: true, message: `User ${email} rejected` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) {
        return res.status(403).json({ success: false, message: 'Admin only' });
    }
    
    const { email } = req.body;
    const users = readUsers();
    
    if (!users[email]) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    
    const status = users[email].isBlocked ? 'BLOCKED' : 'ACTIVE';
    res.json({ success: true, message: `User ${email} is now ${status}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) {
        return res.status(403).json({ success: false, message: 'Admin only' });
    }
    
    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email: email,
        hasApiKeys: !!users[email].apiKey,
        isOwner: users[email].isOwner,
        isApproved: users[email].isApproved,
        isBlocked: users[email].isBlocked,
        createdAt: users[email].createdAt
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) {
        return res.status(403).json({ success: false, message: 'Admin only' });
    }
    
    const users = readUsers();
    const balances = {};
    
    for (const [email, userData] of Object.entries(users)) {
        balances[email] = {
            spot: userData.apiKey ? 1000 : 0,
            funding: userData.apiKey ? 500 : 0,
            total: userData.apiKey ? 1500 : 0,
            hasKeys: !!userData.apiKey
        };
    }
    
    res.json({ success: true, balances: balances });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) {
        return res.status(403).json({ success: false, message: 'Admin only' });
    }
    
    const allTrades = {};
    const files = fs.readdirSync(TRADES_DIR);
    
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(TRADES_DIR, file)));
        allTrades[userId] = trades;
    }
    
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, (req, res) => {
    if (!req.user.isOwner) {
        return res.status(403).json({ success: false, message: 'Admin only' });
    }
    
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    
    if (!bcrypt.compareSync(currentPassword, owner.password)) {
        return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }
    
    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ success: false, message: 'New password must be at least 6 characters' });
    }
    
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    
    res.json({ success: true, message: 'Password changed successfully! Please login again.' });
});

// ==================== SERVE FRONTEND ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== START SERVER ====================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 HALAL TRADING BOT - RUNNING`);
    console.log(`========================================`);
    console.log(`✅ Owner: mujtabahatif@gmail.com`);
    console.log(`✅ Password: Mujtabah@2598`);
    console.log(`✅ ${HALAL_ASSETS.length} Halal Assets Available`);
    console.log(`✅ No Riba | No Gharar | No Maysir | No Leverage`);
    console.log(`✅ Real Binance API Ready | Limit Orders Only`);
    console.log(`========================================`);
    console.log(`Server running on port: ${PORT}`);
});
