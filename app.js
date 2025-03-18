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
  // Create users table if not exists
  db.run(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT,
    verification_code TEXT,
    registered INTEGER DEFAULT 0
  )`);
  
  // Check if public_key column exists
  db.all("PRAGMA table_info(users)", (err, rows) => {
    if (err) {
      console.error("Error checking table schema:", err);
      return;
    }
    
    const hasPublicKey = rows.some(row => row.name === 'public_key');
    
    if (!hasPublicKey) {
      console.log("Adding public_key column to users table...");
      db.run("ALTER TABLE users ADD COLUMN public_key TEXT", (err) => {
        if (err) {
          console.error("Failed to add public_key column:", err);
        } else {
          console.log("Successfully added public_key column to users table");
        }
      });
    } else {
      console.log("public_key column already exists in users table");
    }
  });
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

// RSA Encryption/Decryption functions
function encryptWithPublicKey(publicKey, data) {
  const encryptedData = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(data)
  );
  return encryptedData.toString('base64');
}

function decryptWithPrivateKey(privateKey, data) {
  const decryptedData = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(data, 'base64')
  );
  return decryptedData.toString();
}

// Hybrid encryption functions
// Generate a random AES key
function generateAESKey() {
  return crypto.randomBytes(32); // 256-bit key
}

// Encrypt data with AES-GCM
function encryptWithAES(key, data) {
  const iv = crypto.randomBytes(12); // 12 bytes IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag();
  
  return {
    iv: iv.toString('base64'),
    encryptedData: encrypted,
    authTag: authTag.toString('base64')
  };
}

// Decrypt data with AES-GCM
function decryptWithAES(key, iv, encryptedData, authTag) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm', 
    key, 
    Buffer.from(iv, 'base64')
  );
  
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));
  
  let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// Hybrid encryption using both RSA and AES
function hybridEncrypt(publicKey, data) {
  // Generate a random AES key
  const aesKey = generateAESKey();
  
  // Encrypt the data with AES
  const { iv, encryptedData, authTag } = encryptWithAES(aesKey, data);
  
  // Encrypt the AES key with RSA
  const encryptedKey = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    aesKey
  ).toString('base64');
  
  // Return the encrypted package
  return {
    encryptedKey,
    iv,
    encryptedData,
    authTag
  };
}

// Hybrid decryption using both RSA and AES
function hybridDecrypt(privateKey, encryptedPackage) {
  const { encryptedKey, iv, encryptedData, authTag } = encryptedPackage;
  
  // Decrypt the AES key with RSA
  const aesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(encryptedKey, 'base64')
  );
  
  // Decrypt the data with AES
  return decryptWithAES(aesKey, iv, encryptedData, authTag);
}

// Load or generate server keys
const serverKeys = loadOrGenerateKeys();

// Display server public key for client setup
console.log('Server started. Server public key:');
console.log(serverKeys.publicKey);

// Use JSON middleware
app.use(express.json());

// Get server public key endpoint
app.get('/api/server-public-key', (req, res) => {
  res.json({ 
    publicKey: serverKeys.publicKey
  });
});

// Register client public key endpoint
app.post('/api/register-client-key', (req, res) => {
  try {
    const { username, publicKey } = req.body;
    
    if (!username || !publicKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Store the client's public key
    db.run(
      'UPDATE users SET public_key = ? WHERE username = ?',
      [publicKey, username],
      function(err) {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Failed to register public key' });
        }
        
        if (this.changes === 0) {
          // Create a new user entry if it doesn't exist
          db.run(
            'INSERT INTO users (username, public_key, registered) VALUES (?, ?, 0)',
            [username, publicKey],
            (err) => {
              if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to register public key' });
              }
              
              res.json({ 
                success: true, 
                message: 'Public key registered successfully' 
              });
            }
          );
        } else {
          res.json({ 
            success: true, 
            message: 'Public key updated successfully' 
          });
        }
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User registration endpoint - Step 1
app.post('/api/register', async (req, res) => {
  try {
    const { encryptedData } = req.body;
    
    if (!encryptedData) {
      return res.status(400).json({ error: 'Missing encrypted data' });
    }
    
    // Decrypt the request data using the server's private key
    let decryptedData;
    try {
      decryptedData = JSON.parse(decryptWithPrivateKey(serverKeys.privateKey, encryptedData));
    } catch (error) {
      console.error('Decryption error:', error);
      return res.status(400).json({ error: 'Invalid encrypted data' });
    }
    
    const { username, password } = decryptedData;
    
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
      
      // Get the user's public key
      const publicKey = user ? user.public_key : null;
      
      if (!publicKey) {
        return res.status(400).json({ 
          error: 'Client public key not registered. Please register your public key first.' 
        });
      }
      
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
            
            // Print verification code to server console (for development)
            console.log(`Verification code for ${username}: ${verificationCode}`);
            
            // Create verification response payload
            const responsePayload = JSON.stringify({ verificationCode });
            
            // Use hybrid encryption for the verification code
            const encryptedVerificationCode = hybridEncrypt(publicKey, responsePayload);
            
            return res.json({ 
              success: true, 
              encryptedVerificationCode,
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
            
            // Print verification code to server console (for development)
            console.log(`Verification code for ${username}: ${verificationCode}`);
            
            // Create verification response payload
            const responsePayload = JSON.stringify({ verificationCode });
            
            // Use hybrid encryption for the verification code
            const encryptedVerificationCode = hybridEncrypt(publicKey, responsePayload);
            
            return res.json({ 
              success: true,
              encryptedVerificationCode,
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
    const { encryptedData } = req.body;
    
    if (!encryptedData) {
      return res.status(400).json({ error: 'Missing encrypted data' });
    }
    
    // Decrypt the request data using the server's private key
    let decryptedData;
    try {
      decryptedData = JSON.parse(decryptWithPrivateKey(serverKeys.privateKey, encryptedData));
    } catch (error) {
      console.error('Decryption error:', error);
      return res.status(400).json({ error: 'Invalid encrypted data' });
    }
    
    const { username, verificationCode } = decryptedData;
    
    if (!username || !verificationCode) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Check verification code
    db.get(
      'SELECT verification_code, public_key FROM users WHERE username = ? AND registered = 0',
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
            
            // Create response payload
            const responsePayload = JSON.stringify({ 
              success: true, 
              message: 'Registration complete. You can now log in.'
            });
            
            // Use hybrid encryption for the response
            const encryptedResponse = hybridEncrypt(user.public_key, responsePayload);
            
            return res.json({ encryptedResponse });
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
    const { encryptedData } = req.body;
    
    if (!encryptedData) {
      return res.status(400).json({ error: 'Missing encrypted data' });
    }
    
    // Decrypt the request data using the server's private key
    let decryptedData;
    try {
      decryptedData = JSON.parse(decryptWithPrivateKey(serverKeys.privateKey, encryptedData));
    } catch (error) {
      console.error('Decryption error:', error);
      return res.status(400).json({ error: 'Invalid encrypted data' });
    }
    
    const { username, password } = decryptedData;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Missing credentials' });
    }
    
    // Verify credentials
    db.get(
      'SELECT password_hash, public_key FROM users WHERE username = ? AND registered = 1',
      [username],
      async (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Server error' });
        }
        
        if (!user) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (!user.public_key) {
          return res.status(400).json({ error: 'Client public key not found' });
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
        
        // Create response payload
        const responsePayload = JSON.stringify({ 
          success: true, 
          token,
          message: 'Login successful'
        });
        
        // Use hybrid encryption for the response
        const encryptedResponse = hybridEncrypt(user.public_key, responsePayload);
        
        res.json({ encryptedResponse });
      }
    );
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add a middleware for protected routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication token required' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET || 'default_jwt_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    req.user = user;
    next();
  });
}


// Add these additional imports if needed
const multer = require('multer');
const sharp = require('sharp');
const { v4: uuidv4 } = require('uuid');

// Initialize necessary directories
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Create directories if they don't exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Set up multer storage configuration
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    // Create a temp directory for uploads
    const tempDir = path.join(UPLOADS_DIR, 'temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    cb(null, tempDir);
  },
  filename: function(req, file, cb) {
    // Create a unique filename
    const uniqueName = uuidv4() + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

// Configure multer file filter and limits
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10 MB limit
  },
  fileFilter: function(req, file, cb) {
    // Accept only image files
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
      return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
  }
});

// Initialize the images table in the database
db.serialize(() => {
  // Create images table if not exists
  db.run(`CREATE TABLE IF NOT EXISTS images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    original_filename TEXT,
    storage_filename TEXT,
    path TEXT,
    size INTEGER,
    resolution TEXT,
    upload_date INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(username)
  )`);
});

// Image upload endpoint
app.post('/api/upload', upload.single('image'), async (req, res) => {
  try {
    // Extract auth and metadata from request
    const authHeader = req.body.auth;
    const encryptedMetadata = req.body.metadata;
    const imageFile = req.file;

    // Check if all required fields are present
    if (!authHeader || !encryptedMetadata || !imageFile) {
      // Clean up uploaded file if it exists
      if (imageFile && imageFile.path) {
        fs.unlink(imageFile.path, (err) => {
          if (err) console.error('Error deleting temp file:', err);
        });
      }
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Process the authentication token
    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.JWT_SECRET || 'default_jwt_secret', async (err, user) => {
      if (err) {
        // Clean up the uploaded file
        fs.unlink(imageFile.path, (err) => {
          if (err) console.error('Error deleting temp file:', err);
        });
        return res.status(403).json({ error: 'Invalid or expired token' });
      }

      try {
        // Decrypt the metadata
        const decryptedMetadata = JSON.parse(decryptWithPrivateKey(serverKeys.privateKey, encryptedMetadata));
        const { fileName, size, resolution } = decryptedMetadata;

        // Process and store the image
        const imageInfo = await processAndStoreImage(imageFile.path, fileName, user.username);
        
        // Save image metadata to database
        const dbImageId = await saveImageToDatabase(user.username, fileName, imageInfo);

        // Get user's public key for encrypting the response
        const userPublicKey = await getUserPublicKey(user.username);
        
        if (!userPublicKey) {
          return res.status(400).json({ error: 'User public key not found' });
        }

        // Create and encrypt the response
        const responseData = JSON.stringify({
          success: true,
          remoteUrl: `/api/images/${dbImageId}`,
          message: 'Image uploaded successfully'
        });

        // Encrypt the response using hybrid encryption
        const encryptedResponse = hybridEncrypt(userPublicKey, responseData);

        // Send the encrypted response to the client
        res.json({ encryptedResponse });

      } catch (error) {
        console.error('Error processing upload:', error);
        
        // Clean up the uploaded file
        if (imageFile && imageFile.path) {
          fs.unlink(imageFile.path, (err) => {
            if (err) console.error('Error deleting temp file:', err);
          });
        }
        
        res.status(500).json({ error: 'Error processing upload: ' + error.message });
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Server error during upload' });
  }
});

// Function to process and store the uploaded image
async function processAndStoreImage(tempPath, originalFilename, username) {
  try {
    // Generate a unique filename
    const storageFilename = `${uuidv4()}${path.extname(originalFilename)}`;
    
    // Create user directory if it doesn't exist
    const userDir = path.join(UPLOADS_DIR, username);
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    
    // Define the path where the image will be stored
    const storagePath = path.join(userDir, storageFilename);
    
    // Get image metadata
    const metadata = await sharp(tempPath).metadata();
    
    // Resize and optimize the image
    await sharp(tempPath)
      .resize({
        width: Math.min(metadata.width, 1920),
        height: Math.min(metadata.height, 1080),
        fit: 'inside',
        withoutEnlargement: true
      })
      .jpeg({ quality: 85 })
      .toFile(storagePath);
    
    // Delete the temporary file
    fs.unlink(tempPath, (err) => {
      if (err) console.error('Error deleting temp file:', err);
    });
    
    // Get the file size
    const stats = fs.statSync(storagePath);
    
    return {
      path: storagePath,
      storagePath: path.join(username, storageFilename).replace(/\\/g, '/'),
      storageFilename: storageFilename,
      size: stats.size,
      resolution: `${metadata.width}x${metadata.height}`
    };
  } catch (error) {
    console.error('Error processing image:', error);
    throw error;
  }
}

// Function to save image metadata to the database
function saveImageToDatabase(username, originalFilename, imageInfo) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO images (user_id, original_filename, storage_filename, path, size, resolution, upload_date)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        username,
        originalFilename,
        imageInfo.storageFilename,
        imageInfo.storagePath,
        imageInfo.size,
        imageInfo.resolution,
        Date.now()
      ],
      function(err) {
        if (err) {
          return reject(err);
        }
        
        resolve(this.lastID);
      }
    );
  });
}

// Function to get a user's public key from the database
function getUserPublicKey(username) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT public_key FROM users WHERE username = ?',
      [username],
      (err, row) => {
        if (err) {
          return reject(err);
        }
        
        if (!row) {
          return resolve(null);
        }
        
        resolve(row.public_key);
      }
    );
  });
}

// Endpoint to retrieve images by ID
app.get('/api/images/:id', authenticateToken, (req, res) => {
  const imageId = req.params.id;
  const username = req.user.username;
  
  // Verify that the user has access to this image
  db.get(
    'SELECT * FROM images WHERE id = ? AND user_id = ?',
    [imageId, username],
    (err, image) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      
      if (!image) {
        return res.status(404).json({ error: 'Image not found or access denied' });
      }
      
      // Send the image file
      res.sendFile(path.join(UPLOADS_DIR, image.path));
    }
  );
});



// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});