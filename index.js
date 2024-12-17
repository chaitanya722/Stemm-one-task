// Import required modules
const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const helmet = require('helmet');
const compression = require('compression');
const NodeCache = require('node-cache');

// Initialize app and cache
const app = express();
const cache = new NodeCache({ stdTTL: 60 }); // Cache for 60 seconds

// Middleware
app.use(express.json());
app.use(morgan('dev')); 
app.use(helmet()); 
app.use(compression()); 

const SECRET_KEY = '88888888';


function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests, please try again later.',
});
app.use(limiter);

const users = [
  { id: 1, username: 'admin', role: 'admin' },
  { id: 2, username: 'editor', role: 'editor' },
  { id: 3, username: 'viewer', role: 'viewer' },
];

app.post('/login', (req, res) => {
  const { username } = req.body;
  const user = users.find((u) => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

app.get('/protected', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  res.json({ message: 'Welcome, Admin!' });
});

// Cache Middleware
function cacheMiddleware(req, res, next) {
  const key = req.originalUrl;
  const cachedData = cache.get(key);
  if (cachedData) {
    return res.json(cachedData);
  }
  res.sendResponse = res.json;
  res.json = (body) => {
    cache.set(key, body);
    res.sendResponse(body);
  };
  next();
}

app.get('/data', cacheMiddleware, (req, res) => {
  const data = { message: 'This is cached data.', timestamp: new Date() };
  res.json(data);
});



// Load Balancing Example (Round-Robin)
const backendServers = [
  'http://backend1.example.com',
  'http://backend2.example.com',
];
let currentServerIndex = 0;

function getNextServer() {
  const server = backendServers[currentServerIndex];
  currentServerIndex = (currentServerIndex + 1) % backendServers.length;
  return server;
}

app.get('/balance', (req, res) => {
  const server = getNextServer();
  res.json({ message: 'Request forwarded to server', server });
});

// Security (HTTPS enforcement would be done at a reverse proxy level like NGINX)
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the secure API!' });
});

// Start Server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
