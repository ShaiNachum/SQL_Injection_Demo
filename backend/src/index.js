import express from 'express'     // Express framework - the foundation of our server
import cors from 'cors'           // CORS middleware - allows frontend to communicate with backend
import dotenv from 'dotenv'       // Environment variable loader - for configuration
import authRoutes from './routes/auth.routes.js'  // Our authentication routes
import { initializeDatabase } from './db/database.js'  // Database initialization function

// Load environment variables from .env file
dotenv.config()

// Initialize express app - create our server
const app = express()
const PORT = process.env.PORT || 5000

// Initialize database - set up our data storage
initializeDatabase()

// Enable CORS - Cross-Origin Resource Sharing
app.use(cors())

// Parse JSON request bodies
app.use(express.json())

// Logger middleware - logs all requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`)
  next()
})

// Authentication routes - handle login, register, etc.
// Mount all auth routes at "/api/auth/*" 
app.use('/api/auth', authRoutes)

// Default route - home page
app.get('/', (req, res) => {
  res.json({ message: 'SQL Injection Demo API is running' })
})

// Start the server - begin accepting requests
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
  console.log(`Visit http://localhost:${PORT}/ to check server status`)
})