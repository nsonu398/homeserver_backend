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





// Add these packages to your existing imports
const multer = require('multer');
const sharp = require('sharp');

// Create necessary directories
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const THUMBNAILS_DIR = path.join(__dirname, 'thumbnails');

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}
if (!fs.existsSync(THUMBNAILS_DIR)) {
  fs.mkdirSync(THUMBNAILS_DIR, { recursive: true });
}

// Setup multer for memory storage (for encrypted uploads)
const memoryStorage = multer.memoryStorage();
const encryptedUpload = multer({
  storage: memoryStorage,
  limits: {
    fileSize: 15 * 1024 * 1024 // 15MB limit to accommodate encrypted data
  }
});

// Add this to your db.serialize() function where you create tables
db.run(`CREATE TABLE IF NOT EXISTS images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  original_name TEXT,
  user_username TEXT NOT NULL,
  upload_date INTEGER NOT NULL,
  original_date TEXT,
  content_type TEXT,
  file_size INTEGER,
  FOREIGN KEY(user_username) REFERENCES users(username)
)`);

// Helper function to encrypt image buffer for sending to client
function encryptImageForResponse(imageBuffer, clientPublicKey) {
  // We'll use AES for the image data due to size
  const aesKey = generateAESKey();
  const iv = crypto.randomBytes(12); // 12 bytes IV for GCM
  
  // Encrypt the image with AES-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encryptedImage = Buffer.concat([
    cipher.update(imageBuffer),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  
  // Encrypt the AES key with the client's public RSA key
  const encryptedKey = crypto.publicEncrypt(
    {
      key: clientPublicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    aesKey
  );
  
  // Return everything needed for decryption
  return {
    encryptedImage: encryptedImage.toString('base64'),
    encryptedKey: encryptedKey.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

// Helper function to create JSON response encrypted with client's public key
function createEncryptedResponse(responseData, clientPublicKey) {
  const jsonString = JSON.stringify(responseData);
  return { encryptedResponse: hybridEncrypt(clientPublicKey, jsonString) };
}

// 1. UPLOAD ENCRYPTED IMAGE
app.post('/api/images/upload/encrypted', authenticateToken, encryptedUpload.single('encryptedImage'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No encrypted image uploaded' });
    }
    
    // Get user's public key
    db.get('SELECT public_key FROM users WHERE username = ?', [req.user.username], async (err, user) => {
      if (err || !user || !user.public_key) {
        return res.status(400).json({ error: 'User public key not found' });
      }
      
      try {
        // Decrypt the encryption parameters from the request
        const encryptedParams = req.body.encryptionParams;
        if (!encryptedParams) {
          return res.status(400).json({ error: 'Missing encryption parameters' });
        }
        
        let params;
        try {
          // Decrypt using the server's private key
          const decryptedParams = decryptWithPrivateKey(serverKeys.privateKey, encryptedParams);
          params = JSON.parse(decryptedParams);
        } catch (decryptionError) {
          console.error('Failed to decrypt parameters:', decryptionError);
          return res.status(400).json({ error: 'Invalid encryption parameters' });
        }
        
        const { encryptedKey, iv, authTag, originalName, contentType, originalDate } = params;
        
        if (!encryptedKey || !iv || !authTag) {
          return res.status(400).json({ error: 'Incomplete encryption parameters' });
        }
        
        // Decrypt the AES key using server's private key
        const aesKey = crypto.privateDecrypt(
          {
            key: serverKeys.privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
          },
          Buffer.from(encryptedKey, 'base64')
        );
        
        // Decrypt the image using AES
        const ivBuffer = Buffer.from(iv, 'base64');
        const authTagBuffer = Buffer.from(authTag, 'base64');
        
        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, ivBuffer);
        decipher.setAuthTag(authTagBuffer);
        
        const decryptedImage = Buffer.concat([
          decipher.update(req.file.buffer),
          decipher.final()
        ]);
        
        // Generate a unique filename and save the decrypted image
        const fileExt = path.extname(originalName || '.jpg');
        const filename = `image-${Date.now()}-${Math.round(Math.random() * 1E9)}${fileExt}`;
        const filepath = path.join(UPLOADS_DIR, filename);
        
        fs.writeFileSync(filepath, decryptedImage);
        
        // Save image metadata to database
        db.run(
          'INSERT INTO images (filename, original_name, user_username, upload_date, original_date, content_type, file_size) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [
            filename,
            originalName || filename,
            req.user.username,
            Date.now(),
            originalDate || new Date().toISOString(),
            contentType || 'image/jpeg',
            decryptedImage.length
          ],
          function(err) {
            if (err) {
              console.error('Database error:', err);
              // Clean up the file if database insert failed
              fs.unlinkSync(filepath);
              return res.status(500).json({ error: 'Failed to save image metadata' });
            }
            
            const imageId = this.lastID;
            
            // Create success response
            const responseData = {
              success: true,
              message: 'Image uploaded successfully',
              id: imageId,
              filename: filename
            };
            
            // Return encrypted response
            res.json(createEncryptedResponse(responseData, user.public_key));
          }
        );
      } catch (error) {
        console.error('Image processing error:', error);
        res.status(500).json({ error: 'Failed to process encrypted image' });
      }
    });
  } catch (error) {
    console.error('Encrypted upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// 2. GET GALLERY (ENCRYPTED RESPONSE)
app.get('/api/images/gallery/encrypted', authenticateToken, (req, res) => {
  try {
    // Get user's public key
    db.get('SELECT public_key FROM users WHERE username = ?', [req.user.username], (err, user) => {
      if (err || !user || !user.public_key) {
        return res.status(400).json({ error: 'User public key not found' });
      }
      
      // Get all images for this user
      db.all(
        'SELECT id, filename, original_name, upload_date, original_date, content_type, file_size FROM images WHERE user_username = ? ORDER BY upload_date DESC',
        [req.user.username],
        (err, images) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to retrieve gallery' });
          }
          
          // Format images for response
          const galleryData = {
            success: true,
            count: images.length,
            images: images.map(img => ({
              id: img.id,
              originalName: img.original_name,
              uploadDate: img.upload_date,
              originalDate: img.original_date,
              contentType: img.content_type,
              fileSize: img.file_size
            }))
          };
          
          // Send encrypted response
          res.json(createEncryptedResponse(galleryData, user.public_key));
        }
      );
    });
  } catch (error) {
    console.error('Gallery retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve gallery' });
  }
});

// 3. GET ENCRYPTED IMAGE
app.get('/api/images/:id/encrypted', authenticateToken, (req, res) => {
  try {
    const imageId = req.params.id;
    
    // Get user's public key
    db.get('SELECT public_key FROM users WHERE username = ?', [req.user.username], (err, user) => {
      if (err || !user || !user.public_key) {
        return res.status(400).json({ error: 'User public key not found' });
      }
      
      // Get image metadata
      db.get(
        'SELECT filename, content_type, user_username FROM images WHERE id = ?',
        [imageId],
        (err, image) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to retrieve image metadata' });
          }
          
          if (!image) {
            return res.status(404).json({ error: 'Image not found' });
          }
          
          // Verify ownership
          if (image.user_username !== req.user.username) {
            return res.status(403).json({ error: 'Unauthorized access to image' });
          }
          
          try {
            // Read the image file
            const imagePath = path.join(UPLOADS_DIR, image.filename);
            if (!fs.existsSync(imagePath)) {
              return res.status(404).json({ error: 'Image file not found on server' });
            }
            
            const imageBuffer = fs.readFileSync(imagePath);
            
            // Encrypt the image for the client
            const encryptedData = encryptImageForResponse(imageBuffer, user.public_key);
            
            // Add metadata and send response
            res.json({
              success: true,
              contentType: image.content_type || 'image/jpeg',
              ...encryptedData
            });
          } catch (error) {
            console.error('Image encryption error:', error);
            res.status(500).json({ error: 'Failed to encrypt image for response' });
          }
        }
      );
    });
  } catch (error) {
    console.error('Image retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve image' });
  }
});

// 4. GET ENCRYPTED THUMBNAIL
app.get('/api/images/:id/thumbnail/encrypted', authenticateToken, async (req, res) => {
  try {
    const imageId = req.params.id;
    
    // Get user's public key
    db.get('SELECT public_key FROM users WHERE username = ?', [req.user.username], async (err, user) => {
      if (err || !user || !user.public_key) {
        return res.status(400).json({ error: 'User public key not found' });
      }
      
      // Get image metadata
      db.get(
        'SELECT filename, user_username FROM images WHERE id = ?',
        [imageId],
        async (err, image) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to retrieve image metadata' });
          }
          
          if (!image) {
            return res.status(404).json({ error: 'Image not found' });
          }
          
          // Verify ownership
          if (image.user_username !== req.user.username) {
            return res.status(403).json({ error: 'Unauthorized access to image' });
          }
          
          try {
            // Path to original image and thumbnail
            const imagePath = path.join(UPLOADS_DIR, image.filename);
            const thumbnailPath = path.join(THUMBNAILS_DIR, `thumb_${image.filename}`);
            
            // Check if original image exists
            if (!fs.existsSync(imagePath)) {
              return res.status(404).json({ error: 'Image file not found on server' });
            }
            
            let thumbnailBuffer;
            
            // Check if thumbnail already exists
            if (fs.existsSync(thumbnailPath)) {
              thumbnailBuffer = fs.readFileSync(thumbnailPath);
            } else {
              // Generate thumbnail
              thumbnailBuffer = await sharp(imagePath)
                .resize(200, 200, { fit: 'cover' })
                .jpeg({ quality: 80 })
                .toBuffer();
              
              // Save for future use
              fs.writeFileSync(thumbnailPath, thumbnailBuffer);
            }
            
            // Encrypt the thumbnail for the client
            const encryptedData = encryptImageForResponse(thumbnailBuffer, user.public_key);
            
            // Send response
            res.json({
              success: true,
              contentType: 'image/jpeg',
              ...encryptedData
            });
          } catch (error) {
            console.error('Thumbnail processing error:', error);
            res.status(500).json({ error: 'Failed to process thumbnail' });
          }
        }
      );
    });
  } catch (error) {
    console.error('Thumbnail retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve thumbnail' });
  }
});

// 5. SYNC STATUS (ENCRYPTED)
app.get('/api/sync/status/encrypted', authenticateToken, (req, res) => {
  try {
    // Get user's public key
    db.get('SELECT public_key FROM users WHERE username = ?', [req.user.username], (err, user) => {
      if (err || !user || !user.public_key) {
        return res.status(400).json({ error: 'User public key not found' });
      }
      
      // Get the latest sync timestamp
      db.get(
        'SELECT MAX(upload_date) as last_sync FROM images WHERE user_username = ?',
        [req.user.username],
        (err, result) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to retrieve sync status' });
          }
          
          const responseData = {
            success: true,
            lastSync: result && result.last_sync ? result.last_sync : 0
          };
          
          // Send encrypted response
          res.json(createEncryptedResponse(responseData, user.public_key));
        }
      );
    });
  } catch (error) {
    console.error('Sync status error:', error);
    res.status(500).json({ error: 'Failed to get sync status' });
  }
});

// 6. RECENT IMAGES (ENCRYPTED)
app.post('/api/sync/images/since', authenticateToken, (req, res) => {
  try {
    // Decrypt the request using server's private key
    let decryptedData;
    try {
      decryptedData = JSON.parse(decryptWithPrivateKey(serverKeys.privateKey, req.body.encryptedData));
    } catch (error) {
      console.error('Decryption error:', error);
      return res.status(400).json({ error: 'Invalid encrypted data' });
    }
    
    const { timestamp } = decryptedData;
    if (timestamp === undefined) {
      return res.status(400).json({ error: 'Missing timestamp parameter' });
    }
    
    // Get user's public key
    db.get('SELECT public_key FROM users WHERE username = ?', [req.user.username], (err, user) => {
      if (err || !user || !user.public_key) {
        return res.status(400).json({ error: 'User public key not found' });
      }
      
      // Get images since timestamp
      db.all(
        `SELECT id, filename, original_name, upload_date, original_date, content_type
         FROM images 
         WHERE user_username = ? AND upload_date > ? 
         ORDER BY upload_date DESC`,
        [req.user.username, timestamp],
        (err, images) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to retrieve recent images' });
          }
          
          const responseData = {
            success: true,
            count: images.length,
            images: images.map(img => ({
              id: img.id,
              originalName: img.original_name,
              uploadDate: img.upload_date,
              originalDate: img.original_date,
              contentType: img.content_type
            }))
          };
          
          // Send encrypted response
          res.json(createEncryptedResponse(responseData, user.public_key));
        }
      );
    });
  } catch (error) {
    console.error('Recent images error:', error);
    res.status(500).json({ error: 'Failed to get recent images' });
  }
});

// 7. DELETE IMAGE (ENCRYPTED)
app.post('/api/images/delete', authenticateToken, (req, res) => {
  try {
    // Decrypt the request using server's private key
    let decryptedData;
    try {
      decryptedData = JSON.parse(decryptWithPrivateKey(serverKeys.privateKey, req.body.encryptedData));
    } catch (error) {
      console.error('Decryption error:', error);
      return res.status(400).json({ error: 'Invalid encrypted data' });
    }
    
    const { imageId } = decryptedData;
    if (!imageId) {
      return res.status(400).json({ error: 'Missing image ID' });
    }
    
    // Get user's public key
    db.get('SELECT public_key FROM users WHERE username = ?', [req.user.username], (err, user) => {
      if (err || !user || !user.public_key) {
        return res.status(400).json({ error: 'User public key not found' });
      }
      
      // Verify image ownership and get details
      db.get(
        'SELECT filename, user_username FROM images WHERE id = ?',
        [imageId],
        (err, image) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to retrieve image metadata' });
          }
          
          if (!image) {
            return res.status(404).json({ error: 'Image not found' });
          }
          
          // Verify ownership
          if (image.user_username !== req.user.username) {
            return res.status(403).json({ error: 'Unauthorized access to image' });
          }
          
          // Delete from database
          db.run(
            'DELETE FROM images WHERE id = ?',
            [imageId],
            function(err) {
              if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to delete image from database' });
              }
              
              try {
                // Delete image file
                const imagePath = path.join(UPLOADS_DIR, image.filename);
                if (fs.existsSync(imagePath)) {
                  fs.unlinkSync(imagePath);
                }
                
                // Delete thumbnail if it exists
                const thumbnailPath = path.join(THUMBNAILS_DIR, `thumb_${image.filename}`);
                if (fs.existsSync(thumbnailPath)) {
                  fs.unlinkSync(thumbnailPath);
                }
                
                const responseData = {
                  success: true,
                  message: 'Image deleted successfully'
                };
                
                // Send encrypted response
                res.json(createEncryptedResponse(responseData, user.public_key));
              } catch (fileError) {
                console.error('File deletion error:', fileError);
                
                const responseData = {
                  partialSuccess: true,
                  message: 'Image removed from database but file deletion failed'
                };
                
                res.json(createEncryptedResponse(responseData, user.public_key));
              }
            }
          );
        }
      );
    });
  } catch (error) {
    console.error('Image deletion error:', error);
    res.status(500).json({ error: 'Failed to delete image' });
  }
});



// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});