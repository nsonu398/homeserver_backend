const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Create data directory if it doesn't exist
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Setup SQLite database
const db = new sqlite3.Database(path.join(DATA_DIR, 'gallery.db'));

// Initialize database tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT,
    verification_code TEXT,
    registered INTEGER DEFAULT 0
  )`);
});

// Path for RSA key storage
const KEYS_PATH = path.join(DATA_DIR, 'server_keys.json');

// Function to load or generate server RSA key pair
function loadOrGenerateKeys() {
  try {
    // Check if keys already exist
    if (fs.existsSync(KEYS_PATH)) {
      console.log('Loading existing RSA keys...');
      const keys = JSON.parse(fs.readFileSync(KEYS_PATH, 'utf8'));
      return keys;
    } else {
      // Generate new RSA key pair
      console.log('Generating new RSA keys...');
      const serverKeys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });

      // Save keys to file
      fs.writeFileSync(KEYS_PATH, JSON.stringify(serverKeys, null, 2));
      console.log('RSA keys generated and saved.');
      return serverKeys;
    }
  } catch (error) {
    console.error('Error handling server keys:', error);
    // Fallback to generating new keys if there's an error
    const serverKeys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    return serverKeys;
  }
}

// Load or generate server keys
const serverKeys = loadOrGenerateKeys();

// Display server public key for client setup
console.log('Server started. Server public key:');
console.log(serverKeys.publicKey);

// Use JSON middleware
app.use(express.json());

// User registration endpoint - Step 1
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Check if user already exists
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      
      if (user && user.registered === 1) {
        return res.status(400).json({ error: 'Username already exists' });
      }
      
      // Generate a verification code
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      
      // Hash the password
      const passwordHash = await bcrypt.hash(password, 10);
      
      // Create or update user
      if (user) {
        // Update existing unregistered user
        db.run(
          'UPDATE users SET password_hash = ?, verification_code = ? WHERE username = ?',
          [passwordHash, verificationCode, username],
          (err) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Registration failed' });
            }
            
            // Print verification code to server console
            console.log(`Verification code for ${username}: ${verificationCode}`);
            
            return res.json({ 
              success: true, 
              message: 'Registration initiated. Verification code has been generated.'
            });
          }
        );
      } else {
        // Create new user
        db.run(
          'INSERT INTO users (username, password_hash, verification_code, registered) VALUES (?, ?, ?, 0)',
          [username, passwordHash, verificationCode],
          (err) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Registration failed' });
            }
            
            // Print verification code to server console
            console.log(`Verification code for ${username}: ${verificationCode}`);
            
            return res.json({ 
              success: true, 
              message: 'Registration initiated. Verification code has been generated.'
            });
          }
        );
      }
    });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify registration endpoint - Step 2
app.post('/api/verify_registration', (req, res) => {
  try {
    const { username, verificationCode } = req.body;
    
    if (!username || !verificationCode) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Check verification code
    db.get(
      'SELECT verification_code FROM users WHERE username = ? AND registered = 0',
      [username],
      (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Server error' });
        }
        
        if (!user) {
          return res.status(404).json({ error: 'User not found or already registered' });
        }
        
        if (user.verification_code !== verificationCode) {
          return res.status(400).json({ error: 'Invalid verification code' });
        }
        
        // Mark user as registered
        db.run(
          'UPDATE users SET registered = 1, verification_code = NULL WHERE username = ?',
          [username],
          (err) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Verification failed' });
            }
            
            return res.json({ 
              success: true, 
              message: 'Registration complete. You can now log in.' 
            });
          }
        );
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User login endpoint
app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Missing credentials' });
    }
    
    // Verify credentials
    db.get(
      'SELECT password_hash FROM users WHERE username = ? AND registered = 1',
      [username],
      async (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Server error' });
        }
        
        if (!user) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Compare password
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        
        if (!passwordMatch) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
          { username },
          process.env.JWT_SECRET || 'default_jwt_secret',
          { expiresIn: '7d' }
        );
        
        res.json({ 
          success: true, 
          token, 
          message: 'Login successful' 
        });
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});