// Add this to your app.js file in the server project
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

// Create data directory if it doesn't exist
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Setup SQLite database
const db = new sqlite3.Database(path.join(DATA_DIR, 'gallery.db'));

// Test function to modify the database schema
function testAddPublicKeyColumn() {
    console.log("Testing addition of public_key column to users table...");
    
    db.serialize(() => {
      // Check if column exists first
      db.get("PRAGMA table_info(users)", (err, rows) => {
        if (err) {
          console.error("Error checking table schema:", err);
          return;
        }
        
        const hasPublicKey = rows.some(row => row.name === 'public_key');
        
        if (!hasPublicKey) {
          console.log("public_key column doesn't exist. Adding it now...");
          
          db.run("ALTER TABLE users ADD COLUMN public_key TEXT", (err) => {
            if (err) {
              console.error("Failed to add public_key column:", err);
            } else {
              console.log("Successfully added public_key column to users table");
            }
          });
        } else {
          console.log("public_key column already exists");
        }
      });
    });
  }
  
  // Call this function early in your server startup
  testAddPublicKeyColumn();