import sqlite3 from 'sqlite3'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import bcrypt from 'bcryptjs'         // Password hashing library - for securely storing passwords

// Get the current directory of this file
const __filename = fileURLToPath(import.meta.url)  // Get the file path of current module
const __dirname = dirname(__filename)              // Get the directory name of that path

// Define the database file path
const dbPath = join(__dirname, 'users.db')

// Create a new database connection
const db = new sqlite3.Database(dbPath)

// Initialize the database function - sets up our database structure
export const initializeDatabase = () => {
  // Use serialize to ensure commands run in sequence for making sure we complete one task before starting the next
  db.serialize(() => {
    // Create users table if it doesn't exist
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,  /* Unique identifier for each user - like a unique ID number */
        username TEXT UNIQUE,                  /* Username - must be unique */
        password TEXT,                         /* Password - stored in hashed form */
        email TEXT UNIQUE                      /* Email - must be unique */
      )
    `)

    // Check if there are any users in the database
    db.get('SELECT COUNT(*) as count FROM users', (err, result) => {
      if (err) {
        console.error('Error checking users table:', err)
        return
      }

      // If no users exist (count is 0), create sample users
      if (result.count === 0) {
        console.log('Creating sample users...')
        
        // Hash passwords for secure storage
        const hashPassword = (password) => bcrypt.hashSync(password, 10)
        
        // Sample users with hashed passwords
        const sampleUsers = [
          { username: 'admin', password: hashPassword('admin123'), email: 'admin@example.com' },
          { username: 'user1', password: hashPassword('password123'), email: 'user1@example.com' },
          { username: 'securityuser', password: hashPassword('secure456'), email: 'security@example.com' }
        ]

        // Insert sample users into the database
        const stmt = db.prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)')
        sampleUsers.forEach(user => {
          stmt.run(user.username, user.password, user.email)
        })
        stmt.finalize()
        
        console.log('Sample users created successfully')
      }
    })
  })

  console.log('Database initialized')
}

export default db