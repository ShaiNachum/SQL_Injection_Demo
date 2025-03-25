import express from 'express'
import { vulnerableLogin, secureLogin, getCurrentUser } from '../controllers/auth.controller.js'

// Create a new router object
const router = express.Router()

// Define routes for different authentication endpoints
// Vulnerable endpoint (demonstrates SQL injection vulnerability)
router.post('/vulnerable/login', vulnerableLogin)

// Secure endpoint (demonstrates protection against SQL injection)
router.post('/secure/login', secureLogin)

// Get current user info endpoint - used to retrieve user data with a valid token
router.get('/me', getCurrentUser)

export default router