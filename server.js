const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const os = require('os');
const bcrypt = require('bcryptjs');

// ======================
// ENVIRONMENT CONFIGURATION
// ======================

const NODE_ENV = process.env.NODE_ENV || 'development';
const PUBLIC_URL = process.env.PUBLIC_URL || null;
const PORT = process.env.PORT || 3000;

console.log(`📋 Environment: ${NODE_ENV}`);
console.log(`🌐 Public URL: ${PUBLIC_URL || 'Not set (using local IP)'}\n`);

// ======================
// SETUP
// ======================

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: { origin: '*' }
});

app.use(express.json());
app.use(express.static('.'));

// Data directories
const dataDir = path.join(__dirname, 'competition-data');
const credentialsFile = path.join(__dirname, 'admin-credentials.json');
const sessionsFile = path.join(__dirname, 'admin-sessions.json');

if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// ======================
// CREDENTIALS MANAGEMENT
// ======================

function loadCredentials() {
    try {
        if (fs.existsSync(credentialsFile)) {
            const data = fs.readFileSync(credentialsFile, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
    }
    return null;
}

function saveCredentials(credentials) {
    try {
        fs.writeFileSync(credentialsFile, JSON.stringify(credentials, null, 2));
        return true;
    } catch (error) {
        console.error('Error saving credentials:', error);
        return false;
    }
}

function adminAccountExists() {
    return fs.existsSync(credentialsFile);
}

// Session management
// Sessions are persisted to disk so that restarting the server (e.g. after a
// deployment) doesn't silently invalidate every admin who is currently logged in.
function loadSessions() {
    try {
        if (fs.existsSync(sessionsFile)) {
            const data = JSON.parse(fs.readFileSync(sessionsFile, 'utf8'));
            const now = Date.now();
            const sessions = new Map();
            for (const [token, session] of Object.entries(data)) {
                if (session.expiresAt > now) {
                    sessions.set(token, session);
                }
            }
            return sessions;
        }
    } catch (error) {
        console.error('Error loading admin sessions:', error);
    }
    return new Map();
}

function persistSessions() {
    try {
        fs.writeFileSync(sessionsFile, JSON.stringify(Object.fromEntries(adminSessions), null, 2));
    } catch (error) {
        console.error('Error saving admin sessions:', error);
    }
}

let adminSessions = loadSessions(); // token -> { username, createdAt, expiresAt }

function createSession(username) {
    const token = uuidv4();
    const expiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
    adminSessions.set(token, {
        username,
        createdAt: Date.now(),
        expiresAt
    });
    persistSessions();
    return token;
}

function verifySession(token) {
    if (!token) return null;
    const session = adminSessions.get(token);
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
        adminSessions.delete(token);
        persistSessions();
        return null;
    }
    return session;
}

function getTokenFromRequest(req) {
    // Check header first
    const header = req.headers.authorization;
    if (header && header.startsWith('Bearer ')) {
        return header.substring(7);
    }
    // Check cookies
    if (req.headers.cookie) {
        const cookies = req.headers.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'adminToken') {
                return value;
            }
        }
    }
    return null;
}

// Auth middleware
function requireAdminAuth(req, res, next) {
    const token = getTokenFromRequest(req);
    const session = verifySession(token);
    if (!session) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    req.adminUsername = session.username;
    next();
}

// ======================
// ADMIN AUTHENTICATION ROUTES
// ======================

// Check if admin account exists
app.get('/api/admin/status', (req, res) => {
    res.json({ 
        success: true, 
        adminExists: adminAccountExists() 
    });
});

// Create first admin account (setup)
app.post('/api/admin/setup', async (req, res) => {
    try {
        // Check if admin already exists
        if (adminAccountExists()) {
            return res.json({ 
                success: false, 
                message: 'Admin account already exists' 
            });
        }

        const { username, password } = req.body;

        // Validate
        if (!username || username.length < 3) {
            return res.json({ 
                success: false, 
                message: 'Username must be at least 3 characters' 
            });
        }

        if (!password || password.length < 8) {
            return res.json({ 
                success: false, 
                message: 'Password must be at least 8 characters' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save credentials
        const credentials = {
            username,
            passwordHash: hashedPassword,
            createdAt: Date.now()
        };

        if (saveCredentials(credentials)) {
            console.log(`✅ Admin account created: ${username}`);
            res.json({ success: true });
        } else {
            res.json({ 
                success: false, 
                message: 'Failed to save credentials' 
            });
        }
    } catch (error) {
        console.error('Setup error:', error);
        res.json({ 
            success: false, 
            message: 'Setup failed' 
        });
    }
});

// Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if admin account exists
        if (!adminAccountExists()) {
            return res.json({ 
                success: false, 
                message: 'Admin account not set up yet' 
            });
        }

        // Load credentials
        const credentials = loadCredentials();
        if (!credentials) {
            return res.json({ 
                success: false, 
                message: 'Failed to load credentials' 
            });
        }

        // Check username
        if (username !== credentials.username) {
            return res.json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }

        // Check password
        const passwordMatch = await bcrypt.compare(password, credentials.passwordHash);
        if (!passwordMatch) {
            return res.json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }

        // Create session
        const token = createSession(username);
        res.json({ 
            success: true, 
            token 
        });

    } catch (error) {
        console.error('Login error:', error);
        res.json({ 
            success: false, 
            message: 'Login failed' 
        });
    }
});

// Check auth
app.get('/api/admin/check-auth', (req, res) => {
    const token = getTokenFromRequest(req);
    const session = verifySession(token);
    res.json({ authenticated: !!session });
});

// Get admin info
app.get('/api/admin/info', (req, res) => {
    const token = getTokenFromRequest(req);
    const session = verifySession(token);
    if (!session) {
        return res.status(401).json({ success: false });
    }
    res.json({ username: session.username });
});

// Logout
app.post('/api/admin/logout', (req, res) => {
    const token = getTokenFromRequest(req);
    if (token) {
        adminSessions.delete(token);
        persistSessions();
    }
    res.json({ success: true });
});

// ======================
// COMPETITION MANAGEMENT ROUTES
// ======================

function loadAllCompetitions() {
    try {
        const files = fs.readdirSync(dataDir);
        const competitions = [];
        
        files.forEach(file => {
            if (file.endsWith('.json')) {
                try {
                    const sessionId = file.replace('.json', '');
                    const data = JSON.parse(fs.readFileSync(path.join(dataDir, file), 'utf8'));
                    competitions.push({
                        id: sessionId,
                        status: data.competitionSession?.status || 'unknown',
                        createdAt: data.competitionSession?.createdAt || Date.now(),
                        teams: data.teams || {}
                    });
                } catch (error) {
                    console.error(`Error reading ${file}:`, error);
                }
            }
        });
        
        return competitions.sort((a, b) => b.createdAt - a.createdAt);
    } catch (error) {
        console.error('Error loading competitions:', error);
        return [];
    }
}

function loadCompetition(sessionId) {
    try {
        const filePath = path.join(dataDir, `${sessionId}.json`);
        if (!fs.existsSync(filePath)) return null;
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (error) {
        console.error(`Error loading competition ${sessionId}:`, error);
        return null;
    }
}

function saveCompetition(sessionId, data) {
    try {
        const filePath = path.join(dataDir, `${sessionId}.json`);
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error(`Error saving competition ${sessionId}:`, error);
        return false;
    }
}

// Get all competitions
app.get('/api/admin/competitions', requireAdminAuth, (req, res) => {
    const competitions = loadAllCompetitions();
    res.json({ success: true, competitions });
});

// Start new competition
app.post('/api/admin/start-competition', requireAdminAuth, (req, res) => {
    const sessionId = 'comp-' + uuidv4().substring(0, 8);
    
    const competitionData = {
        competitionSession: {
            id: sessionId,
            createdAt: Date.now(),
            startTime: null,
            pausedAt: null,
            elapsedAtPause: 0,
            finishTime: null,
            status: 'active'
        },
        teams: {}
    };

    if (saveCompetition(sessionId, competitionData)) {
        res.json({ 
            success: true, 
            sessionId,
            url: `${PUBLIC_URL || getLocalIP()}/cyber_competition.html?session=${sessionId}`
        });
    } else {
        res.json({ success: false, message: 'Error creating competition' });
    }
});

// Finish competition
app.post('/api/admin/finish-competition/:sessionId', requireAdminAuth, (req, res) => {
    const { sessionId } = req.params;
    const data = loadCompetition(sessionId);
    
    if (!data) {
        return res.json({ success: false, message: 'Competition not found' });
    }

    data.competitionSession.status = 'finished';
    data.competitionSession.finishTime = Date.now();

    if (saveCompetition(sessionId, data)) {
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'Error finishing competition' });
    }
});

// Archive competition
app.post('/api/admin/archive-competition/:sessionId', requireAdminAuth, (req, res) => {
    const { sessionId } = req.params;
    try {
        const oldPath = path.join(dataDir, `${sessionId}.json`);
        const newPath = path.join(dataDir, `${sessionId}.archived.json`);
        fs.renameSync(oldPath, newPath);
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: 'Error archiving competition' });
    }
});

// Delete competition
app.delete('/api/admin/delete-competition/:sessionId', requireAdminAuth, (req, res) => {
    const { sessionId } = req.params;
    try {
        const filePath = path.join(dataDir, `${sessionId}.json`);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: 'Error deleting competition' });
    }
});

// ======================
// ORIGINAL GAME API ENDPOINTS (Preserved)
// ======================

app.get('/api/server-ip', (req, res) => {
    const interfaces = os.networkInterfaces();
    let ipAddress = 'localhost';
    
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                ipAddress = iface.address;
                break;
            }
        }
        if (ipAddress !== 'localhost') break;
    }
    
    res.json({
        ip: ipAddress,
        port: PORT,
        localhost: 'localhost',
        port_str: ':3000',
        publicUrl: PUBLIC_URL,
        deploymentMode: PUBLIC_URL ? 'cloud' : 'local'
    });
});

app.get('/api/session/new', (req, res) => {
    const sessionId = 'comp-' + uuidv4().substring(0, 8);
    const competitionData = {
        competitionSession: {
            id: sessionId,
            createdAt: Date.now(),
            startTime: null,
            pausedAt: null,
            elapsedAtPause: 0,
            finishTime: null,
            status: 'active'
        },
        teams: {}
    };
    saveCompetition(sessionId, competitionData);
    res.json({ success: true, sessionId });
});

app.get('/api/session/:id', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false, message: 'Session not found' });
    }

    res.json({
        success: true,
        session: data.competitionSession,
        teams: data.teams
    });
});

app.get('/api/leaderboard/:id', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false });
    }

    const leaderboard = Object.values(data.teams || {})
        .sort((a, b) => b.score - a.score)
        .map((team, idx) => ({
            rank: idx + 1,
            ...team
        }));

    res.json({ success: true, leaderboard });
});

app.get('/api/report/:id', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false });
    }

    const report = generateReport(data);
    res.json({ success: true, report });
});

app.post('/api/session/:id/finish', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false });
    }

    data.competitionSession.status = 'finished';
    data.competitionSession.finishTime = Date.now();
    saveCompetition(id, data);

    res.json({ success: true });
});

function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return `http://${iface.address}:${PORT}`;
            }
        }
    }
    return `http://localhost:${PORT}`;
}

function generateReport(data) {
    const leaderboard = Object.values(data.teams || {})
        .sort((a, b) => b.score - a.score)
        .map((team, idx) => ({
            rank: idx + 1,
            ...team
        }));

    const totalTeams = leaderboard.length;
    const finishedTeams = leaderboard.filter(t => t.status === 'finished').length;
    const avgScore = leaderboard.length > 0 
        ? (leaderboard.reduce((sum, t) => sum + t.score, 0) / leaderboard.length).toFixed(2)
        : 0;

    return {
        sessionId: data.competitionSession.id,
        createdAt: data.competitionSession.createdAt,
        finishedAt: data.competitionSession.finishTime,
        duration: data.competitionSession.finishTime 
            ? (data.competitionSession.finishTime - data.competitionSession.startTime) 
            : 0,
        totalDuration: data.competitionSession.finishTime 
            ? (data.competitionSession.finishTime - data.competitionSession.startTime) / 1000 
            : 0,
        statistics: {
            totalTeams,
            finishedTeams,
            averageScore: avgScore,
            highestScore: leaderboard[0]?.score || 0,
            lowestScore: leaderboard[leaderboard.length - 1]?.score || 0
        },
        leaderboard,
        teams: leaderboard.map(team => ({
            name: team.name,
            rank: team.rank,
            score: team.score,
            shield: team.shield,
            status: team.status,
            questionsAnswered: team.questionsAnswered,
            correctAnswers: team.correctAnswers,
            answers: team.answers || {},
            startTime: team.startTime,
            finishTime: team.finishTime
        })),
        teamDetails: leaderboard.map(team => ({
            name: team.name,
            rank: team.rank,
            score: team.score,
            shield: team.shield,
            status: team.status,
            questionsAnswered: team.questionsAnswered,
            correctAnswers: team.correctAnswers,
            accuracy: team.questionsAnswered > 0 
                ? (team.correctAnswers / team.questionsAnswered * 100).toFixed(2) 
                : 0,
            startTime: team.startTime,
            finishTime: team.finishTime,
            completionTime: team.startTime && team.finishTime 
                ? (team.finishTime - team.startTime) / 1000 
                : null
        }))
    };
}

// ======================
// WEBSOCKET (Socket.io)
// ======================

io.on('connection', (socket) => {
    socket.on('join-session', async (data) => {
        const { sessionId, teamName, teamId, isObserver } = data;
        
        const competition = loadCompetition(sessionId);
        if (!competition) {
            socket.emit('error', 'Session not found');
            return;
        }

        socket.join(sessionId);

        if (isObserver) {
            socket.emit('session-data', {
                session: competition.competitionSession,
                teams: competition.teams
            });
        } else {
            if (!competition.teams[teamId]) {
                competition.teams[teamId] = {
                    id: teamId,
                    name: teamName,
                    score: 0,
                    shield: 100,
                    questionsAnswered: 0,
                    correctAnswers: 0,
                    status: 'joined',
                    answers: {},
                    startTime: null,
                    finishTime: null,
                    missionIndex: 0
                };
                saveCompetition(sessionId, competition);
            }

            socket.emit('session-data', competition.competitionSession);
            io.to(sessionId).emit('team-joined', { team: competition.teams[teamId] });
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('start-timer', (data) => {
        const { sessionId } = data;
        const competition = loadCompetition(sessionId);
        if (competition) {
            const now = Date.now();
            competition.competitionSession.startTime = now;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('timer-started', { startTime: now });
            console.log('Timer started for session:', sessionId);
        }
    });

    socket.on('pause-competition', (data) => {
        const { sessionId } = data;
        const competition = loadCompetition(sessionId);
        if (competition) {
            const now = Date.now();
            const elapsedTime = now - competition.competitionSession.startTime;
            competition.competitionSession.pausedAt = now;
            competition.competitionSession.elapsedAtPause = elapsedTime;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('competition-paused', { 
                pausedAt: now,
                elapsedTime: elapsedTime
            });
            console.log('Competition paused. Elapsed:', elapsedTime, 'ms');
        }
    });

    socket.on('resume-competition', (data) => {
        const { sessionId } = data;
        const competition = loadCompetition(sessionId);
        if (competition) {
            const now = Date.now();
            const pauseDuration = now - competition.competitionSession.pausedAt;
            competition.competitionSession.startTime += pauseDuration;
            competition.competitionSession.pausedAt = null;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('competition-resumed', { startTime: competition.competitionSession.startTime });
            console.log('Competition resumed. Pause duration:', pauseDuration, 'ms. New start time adjusted.');
        }
    });

    socket.on('answer-submitted', (data) => {
        const { sessionId, teamId, questionId, isCorrect, points } = data;
        const competition = loadCompetition(sessionId);
        if (competition && competition.teams[teamId]) {
            const team = competition.teams[teamId];
            team.answers[questionId] = isCorrect;
            team.questionsAnswered++;
            if (isCorrect) {
                team.correctAnswers++;
                team.score += points || 25;
            } else {
                team.shield = Math.max(0, team.shield - 8);
            }
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('team-finished', (data) => {
        const { sessionId, teamId } = data;
        const competition = loadCompetition(sessionId);
        if (competition && competition.teams[teamId]) {
            competition.teams[teamId].status = 'finished';
            competition.teams[teamId].finishTime = Date.now();
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('mission-changed', (data) => {
        const { sessionId, teamId, missionIndex } = data;
        const competition = loadCompetition(sessionId);
        if (competition && competition.teams[teamId]) {
            competition.teams[teamId].missionIndex = missionIndex;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('disconnect', () => {
        // Handle disconnect
    });
});

// ======================
// STATIC ROUTES
// ======================

app.get('/', (req, res) => {
    if (adminAccountExists()) {
        res.redirect('/admin/login');
    } else {
        res.redirect('/admin/setup');
    }
});

app.get('/admin/setup', (req, res) => {
    if (adminAccountExists()) {
        res.redirect('/admin/login');
    } else {
        res.sendFile(path.join(__dirname, 'admin-setup.html'));
    }
});

app.get('/admin/login', (req, res) => {
    if (!adminAccountExists()) {
        res.redirect('/admin/setup');
    } else {
        res.sendFile(path.join(__dirname, 'admin-login-v2.html'));
    }
});

app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

app.get('/control-panel.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'control-panel.html'));
});

app.get('/start-competition.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'start-competition.html'));
});

app.get('/competitions.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'competitions.html'));
});

app.get('/account-settings.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'account-settings.html'));
});

// ======================
// START SERVER
// ======================

let localIP = 'localhost';
const interfaces = os.networkInterfaces();

for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
            localIP = iface.address;
            break;
        }
    }
    if (localIP !== 'localhost') break;
}

server.listen(PORT, () => {
    console.log(`\nCompetition Server Started!\n`);
    
    if (PUBLIC_URL) {
        console.log(`CLOUD DEPLOYMENT DETECTED\n`);
        console.log(`Public URL: ${PUBLIC_URL}`);
        console.log(`Admin Portal: ${PUBLIC_URL}/admin/login`);
        console.log(`System is live and accessible worldwide!\n`);
    } else {
        console.log(`LOCAL NETWORK MODE\n`);
        console.log(`Admin Portal (your computer): http://localhost:${PORT}/admin/login`);
        console.log(`Network Access (same WiFi): http://${localIP}:${PORT}/admin/login\n`);
    }
    
    if (adminAccountExists()) {
        console.log(`Admin account exists - Ready to login`);
    } else {
        console.log(`First time setup - Go to ${PUBLIC_URL ? PUBLIC_URL : `http://localhost:${PORT}`}/admin/setup to create admin account`);
    }
    
    console.log(`Competition data stored in: ./competition-data/\n`);
});

module.exports = { app, io };
const sessionsFile = path.join(__dirname, 'admin-sessions.json');

if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// ======================
// CREDENTIALS MANAGEMENT
// ======================

function loadCredentials() {
    try {
        if (fs.existsSync(credentialsFile)) {
            const data = fs.readFileSync(credentialsFile, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
    }
    return null;
}

function saveCredentials(credentials) {
    try {
        fs.writeFileSync(credentialsFile, JSON.stringify(credentials, null, 2));
        return true;
    } catch (error) {
        console.error('Error saving credentials:', error);
        return false;
    }
}

function adminAccountExists() {
    return fs.existsSync(credentialsFile);
}

// Session management
// Sessions are persisted to disk so that restarting the server (e.g. after a
// deployment) doesn't silently invalidate every admin who is currently logged in.
function loadSessions() {
    try {
        if (fs.existsSync(sessionsFile)) {
            const data = JSON.parse(fs.readFileSync(sessionsFile, 'utf8'));
            const now = Date.now();
            const sessions = new Map();
            for (const [token, session] of Object.entries(data)) {
                if (session.expiresAt > now) {
                    sessions.set(token, session);
                }
            }
            return sessions;
        }
    } catch (error) {
        console.error('Error loading admin sessions:', error);
    }
    return new Map();
}

function persistSessions() {
    try {
        fs.writeFileSync(sessionsFile, JSON.stringify(Object.fromEntries(adminSessions), null, 2));
    } catch (error) {
        console.error('Error saving admin sessions:', error);
    }
}

let adminSessions = loadSessions(); // token -> { username, createdAt, expiresAt }

function createSession(username) {
    const token = uuidv4();
    const expiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
    adminSessions.set(token, {
        username,
        createdAt: Date.now(),
        expiresAt
    });
    persistSessions();
    return token;
}

function verifySession(token) {
    if (!token) return null;
    const session = adminSessions.get(token);
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
        adminSessions.delete(token);
        persistSessions();
        return null;
    }
    return session;
}

function getTokenFromRequest(req) {
    // Check header first
    const header = req.headers.authorization;
    if (header && header.startsWith('Bearer ')) {
        return header.substring(7);
    }
    // Check cookies
    if (req.headers.cookie) {
        const cookies = req.headers.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'adminToken') {
                return value;
            }
        }
    }
    return null;
}

// Auth middleware
function requireAdminAuth(req, res, next) {
    const token = getTokenFromRequest(req);
    const session = verifySession(token);
    if (!session) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    req.adminUsername = session.username;
    next();
}

// ======================
// ADMIN AUTHENTICATION ROUTES
// ======================

// Check if admin account exists
app.get('/api/admin/status', (req, res) => {
    res.json({ 
        success: true, 
        adminExists: adminAccountExists() 
    });
});

// Create first admin account (setup)
app.post('/api/admin/setup', async (req, res) => {
    try {
        // Check if admin already exists
        if (adminAccountExists()) {
            return res.json({ 
                success: false, 
                message: 'Admin account already exists' 
            });
        }

        const { username, password } = req.body;

        // Validate
        if (!username || username.length < 3) {
            return res.json({ 
                success: false, 
                message: 'Username must be at least 3 characters' 
            });
        }

        if (!password || password.length < 8) {
            return res.json({ 
                success: false, 
                message: 'Password must be at least 8 characters' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save credentials
        const credentials = {
            username,
            passwordHash: hashedPassword,
            createdAt: Date.now()
        };

        if (saveCredentials(credentials)) {
            console.log(`✅ Admin account created: ${username}`);
            res.json({ success: true });
        } else {
            res.json({ 
                success: false, 
                message: 'Failed to save credentials' 
            });
        }
    } catch (error) {
        console.error('Setup error:', error);
        res.json({ 
            success: false, 
            message: 'Setup failed' 
        });
    }
});

// Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if admin account exists
        if (!adminAccountExists()) {
            return res.json({ 
                success: false, 
                message: 'Admin account not set up yet' 
            });
        }

        // Load credentials
        const credentials = loadCredentials();
        if (!credentials) {
            return res.json({ 
                success: false, 
                message: 'Failed to load credentials' 
            });
        }

        // Check username
        if (username !== credentials.username) {
            return res.json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }

        // Check password
        const passwordMatch = await bcrypt.compare(password, credentials.passwordHash);
        if (!passwordMatch) {
            return res.json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }

        // Create session
        const token = createSession(username);
        res.json({ 
            success: true, 
            token 
        });

    } catch (error) {
        console.error('Login error:', error);
        res.json({ 
            success: false, 
            message: 'Login failed' 
        });
    }
});

// Check auth
app.get('/api/admin/check-auth', (req, res) => {
    const token = getTokenFromRequest(req);
    const session = verifySession(token);
    res.json({ authenticated: !!session });
});

// Get admin info
app.get('/api/admin/info', (req, res) => {
    const token = getTokenFromRequest(req);
    const session = verifySession(token);
    if (!session) {
        return res.status(401).json({ success: false });
    }
    res.json({ username: session.username });
});

// Logout
app.post('/api/admin/logout', (req, res) => {
    const token = getTokenFromRequest(req);
    if (token) {
        adminSessions.delete(token);
        persistSessions();
    }
    res.json({ success: true });
});

// ======================
// COMPETITION MANAGEMENT ROUTES
// ======================

function loadAllCompetitions() {
    try {
        const files = fs.readdirSync(dataDir);
        const competitions = [];
        
        files.forEach(file => {
            if (file.endsWith('.json')) {
                try {
                    const sessionId = file.replace('.json', '');
                    const data = JSON.parse(fs.readFileSync(path.join(dataDir, file), 'utf8'));
                    competitions.push({
                        id: sessionId,
                        status: data.competitionSession?.status || 'unknown',
                        createdAt: data.competitionSession?.createdAt || Date.now(),
                        teams: data.teams || {}
                    });
                } catch (error) {
                    console.error(`Error reading ${file}:`, error);
                }
            }
        });
        
        return competitions.sort((a, b) => b.createdAt - a.createdAt);
    } catch (error) {
        console.error('Error loading competitions:', error);
        return [];
    }
}

function loadCompetition(sessionId) {
    try {
        const filePath = path.join(dataDir, `${sessionId}.json`);
        if (!fs.existsSync(filePath)) return null;
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (error) {
        console.error(`Error loading competition ${sessionId}:`, error);
        return null;
    }
}

function saveCompetition(sessionId, data) {
    try {
        const filePath = path.join(dataDir, `${sessionId}.json`);
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error(`Error saving competition ${sessionId}:`, error);
        return false;
    }
}

// Get all competitions
app.get('/api/admin/competitions', requireAdminAuth, (req, res) => {
    const competitions = loadAllCompetitions();
    res.json({ success: true, competitions });
});

// Start new competition
app.post('/api/admin/start-competition', requireAdminAuth, (req, res) => {
    const sessionId = 'comp-' + uuidv4().substring(0, 8);
    
    const competitionData = {
        competitionSession: {
            id: sessionId,
            createdAt: Date.now(),
            startTime: null,
            pausedAt: null,
            elapsedAtPause: 0,
            finishTime: null,
            status: 'active'
        },
        teams: {}
    };

    if (saveCompetition(sessionId, competitionData)) {
        res.json({ 
            success: true, 
            sessionId,
            url: `${PUBLIC_URL || getLocalIP()}/cyber_competition.html?session=${sessionId}`
        });
    } else {
        res.json({ success: false, message: 'Error creating competition' });
    }
});

// Finish competition
app.post('/api/admin/finish-competition/:sessionId', requireAdminAuth, (req, res) => {
    const { sessionId } = req.params;
    const data = loadCompetition(sessionId);
    
    if (!data) {
        return res.json({ success: false, message: 'Competition not found' });
    }

    data.competitionSession.status = 'finished';
    data.competitionSession.finishTime = Date.now();

    if (saveCompetition(sessionId, data)) {
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'Error finishing competition' });
    }
});

// Archive competition
app.post('/api/admin/archive-competition/:sessionId', requireAdminAuth, (req, res) => {
    const { sessionId } = req.params;
    try {
        const oldPath = path.join(dataDir, `${sessionId}.json`);
        const newPath = path.join(dataDir, `${sessionId}.archived.json`);
        fs.renameSync(oldPath, newPath);
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: 'Error archiving competition' });
    }
});

// Delete competition
app.delete('/api/admin/delete-competition/:sessionId', requireAdminAuth, (req, res) => {
    const { sessionId } = req.params;
    try {
        const filePath = path.join(dataDir, `${sessionId}.json`);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: 'Error deleting competition' });
    }
});

// ======================
// ORIGINAL GAME API ENDPOINTS (Preserved)
// ======================

app.get('/api/server-ip', (req, res) => {
    const interfaces = os.networkInterfaces();
    let ipAddress = 'localhost';
    
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                ipAddress = iface.address;
                break;
            }
        }
        if (ipAddress !== 'localhost') break;
    }
    
    res.json({
        ip: ipAddress,
        port: PORT,
        localhost: 'localhost',
        port_str: ':3000',
        publicUrl: PUBLIC_URL,
        deploymentMode: PUBLIC_URL ? 'cloud' : 'local'
    });
});

app.get('/api/session/new', (req, res) => {
    const sessionId = 'comp-' + uuidv4().substring(0, 8);
    const competitionData = {
        competitionSession: {
            id: sessionId,
            createdAt: Date.now(),
            startTime: null,
            pausedAt: null,
            elapsedAtPause: 0,
            finishTime: null,
            status: 'active'
        },
        teams: {}
    };
    saveCompetition(sessionId, competitionData);
    res.json({ success: true, sessionId });
});

app.get('/api/session/:id', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false, message: 'Session not found' });
    }

    res.json({
        success: true,
        session: data.competitionSession,
        teams: data.teams
    });
});

app.get('/api/leaderboard/:id', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false });
    }

    const leaderboard = Object.values(data.teams || {})
        .sort((a, b) => b.score - a.score)
        .map((team, idx) => ({
            rank: idx + 1,
            ...team
        }));

    res.json({ success: true, leaderboard });
});

app.get('/api/report/:id', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false });
    }

    const report = generateReport(data);
    res.json({ success: true, report });
});

app.post('/api/session/:id/finish', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false });
    }

    data.competitionSession.status = 'finished';
    data.competitionSession.finishTime = Date.now();
    saveCompetition(id, data);

    res.json({ success: true });
});

function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return `http://${iface.address}:${PORT}`;
            }
        }
    }
    return `http://localhost:${PORT}`;
}

function generateReport(data) {
    const leaderboard = Object.values(data.teams || {})
        .sort((a, b) => b.score - a.score)
        .map((team, idx) => ({
            rank: idx + 1,
            ...team
        }));

    const totalTeams = leaderboard.length;
    const finishedTeams = leaderboard.filter(t => t.status === 'finished').length;
    const avgScore = leaderboard.length > 0 
        ? (leaderboard.reduce((sum, t) => sum + t.score, 0) / leaderboard.length).toFixed(2)
        : 0;

    return {
        sessionId: data.competitionSession.id,
        createdAt: data.competitionSession.createdAt,
        finishedAt: data.competitionSession.finishTime,
        duration: data.competitionSession.finishTime 
            ? (data.competitionSession.finishTime - data.competitionSession.startTime) 
            : 0,
        totalDuration: data.competitionSession.finishTime 
            ? (data.competitionSession.finishTime - data.competitionSession.startTime) / 1000 
            : 0,
        statistics: {
            totalTeams,
            finishedTeams,
            averageScore: avgScore,
            highestScore: leaderboard[0]?.score || 0,
            lowestScore: leaderboard[leaderboard.length - 1]?.score || 0
        },
        leaderboard,
        teams: leaderboard.map(team => ({
            name: team.name,
            rank: team.rank,
            score: team.score,
            shield: team.shield,
            status: team.status,
            questionsAnswered: team.questionsAnswered,
            correctAnswers: team.correctAnswers,
            answers: team.answers || {},
            startTime: team.startTime,
            finishTime: team.finishTime
        })),
        teamDetails: leaderboard.map(team => ({
            name: team.name,
            rank: team.rank,
            score: team.score,
            shield: team.shield,
            status: team.status,
            questionsAnswered: team.questionsAnswered,
            correctAnswers: team.correctAnswers,
            accuracy: team.questionsAnswered > 0 
                ? (team.correctAnswers / team.questionsAnswered * 100).toFixed(2) 
                : 0,
            startTime: team.startTime,
            finishTime: team.finishTime,
            completionTime: team.startTime && team.finishTime 
                ? (team.finishTime - team.startTime) / 1000 
                : null
        }))
    };
}

// ======================
// WEBSOCKET (Socket.io)
// ======================

io.on('connection', (socket) => {
    socket.on('join-session', async (data) => {
        const { sessionId, teamName, teamId, isObserver } = data;
        
        const competition = loadCompetition(sessionId);
        if (!competition) {
            socket.emit('error', 'Session not found');
            return;
        }

        socket.join(sessionId);

        if (isObserver) {
            socket.emit('session-data', {
                session: competition.competitionSession,
                teams: competition.teams
            });
        } else {
            if (!competition.teams[teamId]) {
                competition.teams[teamId] = {
                    id: teamId,
                    name: teamName,
                    score: 0,
                    shield: 100,
                    questionsAnswered: 0,
                    correctAnswers: 0,
                    status: 'joined',
                    answers: {},
                    startTime: null,
                    finishTime: null,
                    missionIndex: 0
                };
                saveCompetition(sessionId, competition);
            }

            socket.emit('session-data', competition.competitionSession);
            io.to(sessionId).emit('team-joined', { team: competition.teams[teamId] });
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('start-timer', (data) => {
        const { sessionId } = data;
        const competition = loadCompetition(sessionId);
        if (competition) {
            const now = Date.now();
            competition.competitionSession.startTime = now;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('timer-started', { startTime: now });
            console.log('Timer started for session:', sessionId);
        }
    });

    socket.on('pause-competition', (data) => {
        const { sessionId } = data;
        const competition = loadCompetition(sessionId);
        if (competition) {
            const now = Date.now();
            const elapsedTime = now - competition.competitionSession.startTime;
            competition.competitionSession.pausedAt = now;
            competition.competitionSession.elapsedAtPause = elapsedTime;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('competition-paused', { 
                pausedAt: now,
                elapsedTime: elapsedTime
            });
            console.log('Competition paused. Elapsed:', elapsedTime, 'ms');
        }
    });

    socket.on('resume-competition', (data) => {
        const { sessionId } = data;
        const competition = loadCompetition(sessionId);
        if (competition) {
            const now = Date.now();
            const pauseDuration = now - competition.competitionSession.pausedAt;
            competition.competitionSession.startTime += pauseDuration;
            competition.competitionSession.pausedAt = null;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('competition-resumed', { startTime: competition.competitionSession.startTime });
            console.log('Competition resumed. Pause duration:', pauseDuration, 'ms. New start time adjusted.');
        }
    });

    socket.on('answer-submitted', (data) => {
        const { sessionId, teamId, questionId, isCorrect, points } = data;
        const competition = loadCompetition(sessionId);
        if (competition && competition.teams[teamId]) {
            const team = competition.teams[teamId];
            team.answers[questionId] = isCorrect;
            team.questionsAnswered++;
            if (isCorrect) {
                team.correctAnswers++;
                team.score += points || 25;
            } else {
                team.shield = Math.max(0, team.shield - 8);
            }
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('team-finished', (data) => {
        const { sessionId, teamId } = data;
        const competition = loadCompetition(sessionId);
        if (competition && competition.teams[teamId]) {
            competition.teams[teamId].status = 'finished';
            competition.teams[teamId].finishTime = Date.now();
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('mission-changed', (data) => {
        const { sessionId, teamId, missionIndex } = data;
        const competition = loadCompetition(sessionId);
        if (competition && competition.teams[teamId]) {
            competition.teams[teamId].missionIndex = missionIndex;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('disconnect', () => {
        // Handle disconnect
    });
});

// ======================
// STATIC ROUTES
// ======================

app.get('/', (req, res) => {
    if (adminAccountExists()) {
        res.redirect('/admin/login');
    } else {
        res.redirect('/admin/setup');
    }
});

app.get('/admin/setup', (req, res) => {
    if (adminAccountExists()) {
        res.redirect('/admin/login');
    } else {
        res.sendFile(path.join(__dirname, 'admin-setup.html'));
    }
});

app.get('/admin/login', (req, res) => {
    if (!adminAccountExists()) {
        res.redirect('/admin/setup');
    } else {
        res.sendFile(path.join(__dirname, 'admin-login-v2.html'));
    }
});

app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

app.get('/control-panel.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'control-panel.html'));
});

app.get('/start-competition.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'start-competition.html'));
});

app.get('/competitions.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'competitions.html'));
});

app.get('/account-settings.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'account-settings.html'));
});

// ======================
// START SERVER
// ======================

let localIP = 'localhost';
const interfaces = os.networkInterfaces();

for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
            localIP = iface.address;
            break;
        }
    }
    if (localIP !== 'localhost') break;
}

server.listen(PORT, () => {
    console.log(`\nCompetition Server Started!\n`);
    
    if (PUBLIC_URL) {
        console.log(`CLOUD DEPLOYMENT DETECTED\n`);
        console.log(`Public URL: ${PUBLIC_URL}`);
        console.log(`Admin Portal: ${PUBLIC_URL}/admin/login`);
        console.log(`System is live and accessible worldwide!\n`);
    } else {
        console.log(`LOCAL NETWORK MODE\n`);
        console.log(`Admin Portal (your computer): http://localhost:${PORT}/admin/login`);
        console.log(`Network Access (same WiFi): http://${localIP}:${PORT}/admin/login\n`);
    }
    
    if (adminAccountExists()) {
        console.log(`Admin account exists - Ready to login`);
    } else {
        console.log(`First time setup - Go to ${PUBLIC_URL ? PUBLIC_URL : `http://localhost:${PORT}`}/admin/setup to create admin account`);
    }
    
    console.log(`Competition data stored in: ./competition-data/\n`);
});

module.exports = { app, io };

if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// ======================
// CREDENTIALS MANAGEMENT
// ======================

function loadCredentials() {
    try {
        if (fs.existsSync(credentialsFile)) {
            const data = fs.readFileSync(credentialsFile, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
    }
    return null;
}

function saveCredentials(credentials) {
    try {
        fs.writeFileSync(credentialsFile, JSON.stringify(credentials, null, 2));
        return true;
    } catch (error) {
        console.error('Error saving credentials:', error);
        return false;
    }
}

function adminAccountExists() {
    return fs.existsSync(credentialsFile);
}

// Session management
let adminSessions = new Map(); // token -> { username, createdAt, expiresAt }

function createSession(username) {
    const token = uuidv4();
    const expiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
    adminSessions.set(token, {
        username,
        createdAt: Date.now(),
        expiresAt
    });
    return token;
}

function verifySession(token) {
    if (!token) return null;
    const session = adminSessions.get(token);
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
        adminSessions.delete(token);
        return null;
    }
    return session;
}

function getTokenFromRequest(req) {
    // Check header first
    const header = req.headers.authorization;
    if (header && header.startsWith('Bearer ')) {
        return header.substring(7);
    }
    // Check cookies
    if (req.headers.cookie) {
        const cookies = req.headers.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'adminToken') {
                return value;
            }
        }
    }
    return null;
}

// Auth middleware
function requireAdminAuth(req, res, next) {
    const token = getTokenFromRequest(req);
    const session = verifySession(token);
    if (!session) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    req.adminUsername = session.username;
    next();
}

// ======================
// ADMIN AUTHENTICATION ROUTES
// ======================

// Check if admin account exists
app.get('/api/admin/status', (req, res) => {
    res.json({ 
        success: true, 
        adminExists: adminAccountExists() 
    });
});

// Create first admin account (setup)
app.post('/api/admin/setup', async (req, res) => {
    try {
        // Check if admin already exists
        if (adminAccountExists()) {
            return res.json({ 
                success: false, 
                message: 'Admin account already exists' 
            });
        }

        const { username, password } = req.body;

        // Validate
        if (!username || username.length < 3) {
            return res.json({ 
                success: false, 
                message: 'Username must be at least 3 characters' 
            });
        }

        if (!password || password.length < 8) {
            return res.json({ 
                success: false, 
                message: 'Password must be at least 8 characters' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save credentials
        const credentials = {
            username,
            passwordHash: hashedPassword,
            createdAt: Date.now()
        };

        if (saveCredentials(credentials)) {
            console.log(`✅ Admin account created: ${username}`);
            res.json({ success: true });
        } else {
            res.json({ 
                success: false, 
                message: 'Failed to save credentials' 
            });
        }
    } catch (error) {
        console.error('Setup error:', error);
        res.json({ 
            success: false, 
            message: 'Setup failed' 
        });
    }
});

// Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if admin account exists
        if (!adminAccountExists()) {
            return res.json({ 
                success: false, 
                message: 'Admin account not set up yet' 
            });
        }

        // Load credentials
        const credentials = loadCredentials();
        if (!credentials) {
            return res.json({ 
                success: false, 
                message: 'Failed to load credentials' 
            });
        }

        // Check username
        if (username !== credentials.username) {
            return res.json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }

        // Check password
        const passwordMatch = await bcrypt.compare(password, credentials.passwordHash);
        if (!passwordMatch) {
            return res.json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }

        // Create session
        const token = createSession(username);
        res.json({ 
            success: true, 
            token 
        });

    } catch (error) {
        console.error('Login error:', error);
        res.json({ 
            success: false, 
            message: 'Login failed' 
        });
    }
});

// Check auth
app.get('/api/admin/check-auth', (req, res) => {
    const token = getTokenFromRequest(req);
    const session = verifySession(token);
    res.json({ authenticated: !!session });
});

// Get admin info
app.get('/api/admin/info', (req, res) => {
    const token = getTokenFromRequest(req);
    const session = verifySession(token);
    if (!session) {
        return res.status(401).json({ success: false });
    }
    res.json({ username: session.username });
});

// Logout
app.post('/api/admin/logout', (req, res) => {
    const token = getTokenFromRequest(req);
    if (token) {
        adminSessions.delete(token);
    }
    res.json({ success: true });
});

// ======================
// COMPETITION MANAGEMENT ROUTES
// ======================

function loadAllCompetitions() {
    try {
        const files = fs.readdirSync(dataDir);
        const competitions = [];
        
        files.forEach(file => {
            if (file.endsWith('.json')) {
                try {
                    const sessionId = file.replace('.json', '');
                    const data = JSON.parse(fs.readFileSync(path.join(dataDir, file), 'utf8'));
                    competitions.push({
                        id: sessionId,
                        status: data.competitionSession?.status || 'unknown',
                        createdAt: data.competitionSession?.createdAt || Date.now(),
                        teams: data.teams || {}
                    });
                } catch (error) {
                    console.error(`Error reading ${file}:`, error);
                }
            }
        });
        
        return competitions.sort((a, b) => b.createdAt - a.createdAt);
    } catch (error) {
        console.error('Error loading competitions:', error);
        return [];
    }
}

function loadCompetition(sessionId) {
    try {
        const filePath = path.join(dataDir, `${sessionId}.json`);
        if (!fs.existsSync(filePath)) return null;
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (error) {
        console.error(`Error loading competition ${sessionId}:`, error);
        return null;
    }
}

function saveCompetition(sessionId, data) {
    try {
        const filePath = path.join(dataDir, `${sessionId}.json`);
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error(`Error saving competition ${sessionId}:`, error);
        return false;
    }
}

// Get all competitions
app.get('/api/admin/competitions', requireAdminAuth, (req, res) => {
    const competitions = loadAllCompetitions();
    res.json({ success: true, competitions });
});

// Start new competition
app.post('/api/admin/start-competition', requireAdminAuth, (req, res) => {
    const sessionId = 'comp-' + uuidv4().substring(0, 8);
    
    const competitionData = {
        competitionSession: {
            id: sessionId,
            createdAt: Date.now(),
            startTime: null,
            pausedAt: null,
            elapsedAtPause: 0,
            finishTime: null,
            status: 'active'
        },
        teams: {}
    };

    if (saveCompetition(sessionId, competitionData)) {
        res.json({ 
            success: true, 
            sessionId,
            url: `${PUBLIC_URL || getLocalIP()}/cyber_competition.html?session=${sessionId}`
        });
    } else {
        res.json({ success: false, message: 'Error creating competition' });
    }
});

// Finish competition
app.post('/api/admin/finish-competition/:sessionId', requireAdminAuth, (req, res) => {
    const { sessionId } = req.params;
    const data = loadCompetition(sessionId);
    
    if (!data) {
        return res.json({ success: false, message: 'Competition not found' });
    }

    data.competitionSession.status = 'finished';
    data.competitionSession.finishTime = Date.now();

    if (saveCompetition(sessionId, data)) {
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'Error finishing competition' });
    }
});

// Archive competition
app.post('/api/admin/archive-competition/:sessionId', requireAdminAuth, (req, res) => {
    const { sessionId } = req.params;
    try {
        const oldPath = path.join(dataDir, `${sessionId}.json`);
        const newPath = path.join(dataDir, `${sessionId}.archived.json`);
        fs.renameSync(oldPath, newPath);
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: 'Error archiving competition' });
    }
});

// Delete competition
app.delete('/api/admin/delete-competition/:sessionId', requireAdminAuth, (req, res) => {
    const { sessionId } = req.params;
    try {
        const filePath = path.join(dataDir, `${sessionId}.json`);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: 'Error deleting competition' });
    }
});

// ======================
// ORIGINAL GAME API ENDPOINTS (Preserved)
// ======================

app.get('/api/server-ip', (req, res) => {
    const interfaces = os.networkInterfaces();
    let ipAddress = 'localhost';
    
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                ipAddress = iface.address;
                break;
            }
        }
        if (ipAddress !== 'localhost') break;
    }
    
    res.json({
        ip: ipAddress,
        port: PORT,
        localhost: 'localhost',
        port_str: ':3000',
        publicUrl: PUBLIC_URL,
        deploymentMode: PUBLIC_URL ? 'cloud' : 'local'
    });
});

app.get('/api/session/new', (req, res) => {
    const sessionId = 'comp-' + uuidv4().substring(0, 8);
    const competitionData = {
        competitionSession: {
            id: sessionId,
            createdAt: Date.now(),
            startTime: null,
            pausedAt: null,
            elapsedAtPause: 0,
            finishTime: null,
            status: 'active'
        },
        teams: {}
    };
    saveCompetition(sessionId, competitionData);
    res.json({ success: true, sessionId });
});

app.get('/api/session/:id', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false, message: 'Session not found' });
    }

    res.json({
        success: true,
        session: data.competitionSession,
        teams: data.teams
    });
});

app.get('/api/leaderboard/:id', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false });
    }

    const leaderboard = Object.values(data.teams || {})
        .sort((a, b) => b.score - a.score)
        .map((team, idx) => ({
            rank: idx + 1,
            ...team
        }));

    res.json({ success: true, leaderboard });
});

app.get('/api/report/:id', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false });
    }

    const report = generateReport(data);
    res.json({ success: true, report });
});

app.post('/api/session/:id/finish', (req, res) => {
    const { id } = req.params;
    const data = loadCompetition(id);
    
    if (!data) {
        return res.json({ success: false });
    }

    data.competitionSession.status = 'finished';
    data.competitionSession.finishTime = Date.now();
    saveCompetition(id, data);

    res.json({ success: true });
});

function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return `http://${iface.address}:${PORT}`;
            }
        }
    }
    return `http://localhost:${PORT}`;
}

function generateReport(data) {
    const leaderboard = Object.values(data.teams || {})
        .sort((a, b) => b.score - a.score)
        .map((team, idx) => ({
            rank: idx + 1,
            ...team
        }));

    const totalTeams = leaderboard.length;
    const finishedTeams = leaderboard.filter(t => t.status === 'finished').length;
    const avgScore = leaderboard.length > 0 
        ? (leaderboard.reduce((sum, t) => sum + t.score, 0) / leaderboard.length).toFixed(2)
        : 0;

    return {
        sessionId: data.competitionSession.id,
        createdAt: data.competitionSession.createdAt,
        finishedAt: data.competitionSession.finishTime,
        duration: data.competitionSession.finishTime 
            ? (data.competitionSession.finishTime - data.competitionSession.startTime) 
            : 0,
        totalDuration: data.competitionSession.finishTime 
            ? (data.competitionSession.finishTime - data.competitionSession.startTime) / 1000 
            : 0,
        statistics: {
            totalTeams,
            finishedTeams,
            averageScore: avgScore,
            highestScore: leaderboard[0]?.score || 0,
            lowestScore: leaderboard[leaderboard.length - 1]?.score || 0
        },
        leaderboard,
        teams: leaderboard.map(team => ({
            name: team.name,
            rank: team.rank,
            score: team.score,
            shield: team.shield,
            status: team.status,
            questionsAnswered: team.questionsAnswered,
            correctAnswers: team.correctAnswers,
            answers: team.answers || {},
            startTime: team.startTime,
            finishTime: team.finishTime
        })),
        teamDetails: leaderboard.map(team => ({
            name: team.name,
            rank: team.rank,
            score: team.score,
            shield: team.shield,
            status: team.status,
            questionsAnswered: team.questionsAnswered,
            correctAnswers: team.correctAnswers,
            accuracy: team.questionsAnswered > 0 
                ? (team.correctAnswers / team.questionsAnswered * 100).toFixed(2) 
                : 0,
            startTime: team.startTime,
            finishTime: team.finishTime,
            completionTime: team.startTime && team.finishTime 
                ? (team.finishTime - team.startTime) / 1000 
                : null
        }))
    };
}

// ======================
// WEBSOCKET (Socket.io)
// ======================

io.on('connection', (socket) => {
    socket.on('join-session', async (data) => {
        const { sessionId, teamName, teamId, isObserver } = data;
        
        const competition = loadCompetition(sessionId);
        if (!competition) {
            socket.emit('error', 'Session not found');
            return;
        }

        socket.join(sessionId);

        if (isObserver) {
            socket.emit('session-data', {
                session: competition.competitionSession,
                teams: competition.teams
            });
        } else {
            if (!competition.teams[teamId]) {
                competition.teams[teamId] = {
                    id: teamId,
                    name: teamName,
                    score: 0,
                    shield: 100,
                    questionsAnswered: 0,
                    correctAnswers: 0,
                    status: 'joined',
                    answers: {},
                    startTime: null,
                    finishTime: null,
                    missionIndex: 0
                };
                saveCompetition(sessionId, competition);
            }

            socket.emit('session-data', competition.competitionSession);
            io.to(sessionId).emit('team-joined', { team: competition.teams[teamId] });
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('start-timer', (data) => {
        const { sessionId } = data;
        const competition = loadCompetition(sessionId);
        if (competition) {
            const now = Date.now();
            competition.competitionSession.startTime = now;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('timer-started', { startTime: now });
            console.log('Timer started for session:', sessionId);
        }
    });

    socket.on('pause-competition', (data) => {
        const { sessionId } = data;
        const competition = loadCompetition(sessionId);
        if (competition) {
            const now = Date.now();
            const elapsedTime = now - competition.competitionSession.startTime;
            competition.competitionSession.pausedAt = now;
            competition.competitionSession.elapsedAtPause = elapsedTime;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('competition-paused', { 
                pausedAt: now,
                elapsedTime: elapsedTime
            });
            console.log('Competition paused. Elapsed:', elapsedTime, 'ms');
        }
    });

    socket.on('resume-competition', (data) => {
        const { sessionId } = data;
        const competition = loadCompetition(sessionId);
        if (competition) {
            const now = Date.now();
            const pauseDuration = now - competition.competitionSession.pausedAt;
            competition.competitionSession.startTime += pauseDuration;
            competition.competitionSession.pausedAt = null;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('competition-resumed', { startTime: competition.competitionSession.startTime });
            console.log('Competition resumed. Pause duration:', pauseDuration, 'ms. New start time adjusted.');
        }
    });

    socket.on('answer-submitted', (data) => {
        const { sessionId, teamId, questionId, isCorrect, points } = data;
        const competition = loadCompetition(sessionId);
        if (competition && competition.teams[teamId]) {
            const team = competition.teams[teamId];
            team.answers[questionId] = isCorrect;
            team.questionsAnswered++;
            if (isCorrect) {
                team.correctAnswers++;
                team.score += points || 25;
            } else {
                team.shield = Math.max(0, team.shield - 8);
            }
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('team-finished', (data) => {
        const { sessionId, teamId } = data;
        const competition = loadCompetition(sessionId);
        if (competition && competition.teams[teamId]) {
            competition.teams[teamId].status = 'finished';
            competition.teams[teamId].finishTime = Date.now();
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('mission-changed', (data) => {
        const { sessionId, teamId, missionIndex } = data;
        const competition = loadCompetition(sessionId);
        if (competition && competition.teams[teamId]) {
            competition.teams[teamId].missionIndex = missionIndex;
            saveCompetition(sessionId, competition);
            io.to(sessionId).emit('leaderboard-update', { teams: competition.teams });
        }
    });

    socket.on('disconnect', () => {
        // Handle disconnect
    });
});

// ======================
// STATIC ROUTES
// ======================

app.get('/', (req, res) => {
    if (adminAccountExists()) {
        res.redirect('/admin/login');
    } else {
        res.redirect('/admin/setup');
    }
});

app.get('/admin/setup', (req, res) => {
    if (adminAccountExists()) {
        res.redirect('/admin/login');
    } else {
        res.sendFile(path.join(__dirname, 'admin-setup.html'));
    }
});

app.get('/admin/login', (req, res) => {
    if (!adminAccountExists()) {
        res.redirect('/admin/setup');
    } else {
        res.sendFile(path.join(__dirname, 'admin-login-v2.html'));
    }
});

app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

app.get('/control-panel.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'control-panel.html'));
});

app.get('/start-competition.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'start-competition.html'));
});

app.get('/competitions.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'competitions.html'));
});

app.get('/account-settings.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'account-settings.html'));
});

// ======================
// START SERVER
// ======================

let localIP = 'localhost';
const interfaces = os.networkInterfaces();

for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
            localIP = iface.address;
            break;
        }
    }
    if (localIP !== 'localhost') break;
}

server.listen(PORT, () => {
    console.log(`\nCompetition Server Started!\n`);
    
    if (PUBLIC_URL) {
        console.log(`CLOUD DEPLOYMENT DETECTED\n`);
        console.log(`Public URL: ${PUBLIC_URL}`);
        console.log(`Admin Portal: ${PUBLIC_URL}/admin/login`);
        console.log(`System is live and accessible worldwide!\n`);
    } else {
        console.log(`LOCAL NETWORK MODE\n`);
        console.log(`Admin Portal (your computer): http://localhost:${PORT}/admin/login`);
        console.log(`Network Access (same WiFi): http://${localIP}:${PORT}/admin/login\n`);
    }
    
    if (adminAccountExists()) {
        console.log(`Admin account exists - Ready to login`);
    } else {
        console.log(`First time setup - Go to ${PUBLIC_URL ? PUBLIC_URL : `http://localhost:${PORT}`}/admin/setup to create admin account`);
    }
    
    console.log(`Competition data stored in: ./competition-data/\n`);
});

module.exports = { app, io };
