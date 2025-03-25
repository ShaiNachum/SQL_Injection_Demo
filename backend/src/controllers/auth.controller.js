import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import db from '../db/database.js'

// Generate JWT token for authenticated users
const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: '1h'
  })
}


// VULNERABLE AUTHENTICATION ENDPOINT
export const vulnerableLogin = (req, res) => {
  const { username, password } = req.body
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' })
  }

  // VULNERABLE CODE: Direct string concatenation in SQL query
  // Note the changed order of conditions to allow SQL injection to work properly
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}' OR password = '${password}' AND username = '${username}'`
  
  // Log the generated SQL query for demonstration purposes
  console.log('[VULNERABLE] Generated SQL query:', query)

  // Execute the vulnerable query and get ALL matching results
  db.all(query, (err, users) => {
    if (err) {
      console.error('SQL Error:', err.message)
      return res.status(500).json({ message: 'Database error', error: err.message })
    }

    // If any users are found (which could happen through injection), consider it authenticated
    if (users && users.length > 0) {
      const user = users[0]; // Take the first user for token generation
      const token = generateToken(user.id)
      return res.status(200).json({ 
        message: 'Login successful (VULNERABLE)', 
        user: { 
          id: user.id, 
          username: user.username,
          email: user.email
        },
        allUsers: users, // Send all retrieved users
        token 
      })
    }

    return res.status(401).json({ message: 'Invalid credentials' })
  })
}


// SECURE AUTHENTICATION ENDPOINT

export const secureLogin = (req, res) => {
  // Extract username and password from request body
  let { username, password } = req.body;
  
  // Basic validation - check if username and password are provided
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  // 1. Length validation
  if (username.length > 12 || password.length > 12) {
    return res.status(400).json({ 
      message: 'Input length exceeds maximum allowed characters' 
    });
  }

  // 2. Disallow spaces in username
  if (username.includes(' ') || password.includes(' ') ) {
    return res.status(400).json({ 
      message: 'Username or Password cannot contain spaces' 
    });
  }

  // 3. Check for SQL keywords in username
  const sqlKeywords = [
    'SELECT', 'UPDATE', 'DELETE', 'INSERT', 'DROP', 
    'ALTER', 'CREATE', 'TABLE', 'FROM', 'WHERE', 
    'AND', 'OR', 'UNION', 'JOIN', 'HAVING', 
    'GROUP', 'ORDER', 'BY', '--', ';'
  ];
  
  const normalizedUsername = username.toUpperCase();
  for (const keyword of sqlKeywords) {
    if (normalizedUsername.includes(keyword)) {
      return res.status(400).json({ 
        message: 'Username contains disallowed characters or terms' 
      });
    }
  }

  // Log sanitized login attempt (for monitoring purposes)
  console.log(`[SECURE] Login attempt from username: ${username.substring(0, 3)}***`);

  //Using parameterized query with placeholders
  const query = 'SELECT * FROM users WHERE username = ?';
  
  // Log the prepared statement for demonstration purposes
  console.log('[SECURE] Prepared SQL query:', query, 'with params:', [username]);

  // Execute the secure query with parameters
  db.get(query, [username], (err, user) => {
    if (err) {
      // If there's a database error, log it but don't expose details to client
      console.error('SQL Error:', err.message);
      return res.status(500).json({ message: 'Database error occurred' });
    }

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify password using bcrypt
    const passwordMatch = bcrypt.compareSync(password, user.password);
    
    // If password matches, generate token and return success
    if (passwordMatch) {
      const token = generateToken(user.id);
      return res.status(200).json({ 
        message: 'Login successful (SECURE)', 
        user: { 
          id: user.id, 
          username: user.username,
          email: user.email
        },
        token 
      });
    }

    // Use the same error message as for non-existent username to prevent username enumeration
    return res.status(401).json({ message: 'Invalid credentials' });
  });
};

// Get the current authenticated user information
export const getCurrentUser = (req, res) => {
  const authHeader = req.headers.authorization
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided' })
  }

  const token = authHeader.split(' ')[1]
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    
    // Securely fetch user data
    db.get('SELECT id, username, email FROM users WHERE id = ?', [decoded.userId], (err, user) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' })
      }
      
      if (!user) {
        return res.status(404).json({ message: 'User not found' })
      }
      
      return res.status(200).json({ user })
    })
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' })
  }
}