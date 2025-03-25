# SQL Injection Demo

***Main Page***
![image](https://github.com/user-attachments/assets/c5fe038b-da36-4615-8fcc-ca5ebd7484f9)


***Vulnerable Page***
![image](https://github.com/user-attachments/assets/904fa25f-6462-4ea5-82d7-d292740f573d)


***Secure Page***
![image](https://github.com/user-attachments/assets/93ea0c7b-d757-437d-82f0-7bc79c980f9d)



This project demonstrates the vulnerability of SQL injection attacks and how to prevent them using secure coding practices. It consists of a full-stack application with both vulnerable and secure authentication implementations, providing a clear comparison between unsafe and safe approaches to database interaction.

## Project Overview

The application includes:

- A React frontend with vulnerable and secure login forms.
- A Node.js/Express backend API.
- SQLite database for user storage.
- Visual demonstrations of SQL injection attacks and their prevention.

## Technical Stack

- **Frontend**: React, React Router, Axios, TailwindCSS, DaisyUI.
- **Backend**: Node.js, Express.
- **Database**: SQLite3.
- **Authentication**: JWT (JSON Web Tokens).
- **Password Storage**: bcrypt for hashing.

## Security Demonstration

### SQL Injection Vulnerability

SQL injection is a code injection technique where an attacker can insert malicious SQL statements into input fields that are directly concatenated into SQL queries. This can allow unauthorized access to databases, data theft, data manipulation, or even complete system compromise.

#### Vulnerable Login Implementation

In the vulnerable login implementation:

User input is directly concatenated into the SQL query string:

```javascript
// VULNERABLE CODE - DO NOT USE IN PRODUCTION
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```
This allows attackers to inject SQL code that manipulates the query's logic:

For example, entering `' OR '1'='1` as a username with any password causes the query to become:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'anything'
```

Since `'1'='1'` is always true, this makes the WHERE clause evaluate to true for at least one row, bypassing the authentication.

**Examples of 10 common SQL injection attacks users can try:**
```javascript
  const examples = [
    {
      title: "1. Basic OR Injection",
      value: "' OR '1'='1",
      description:
        "Bypasses authentication by making the WHERE clause always evaluate to true",
    },
    {
      title: "2. Comment-Based Injection",
      value: "admin'--",
      description:
        "Logs in as 'admin' by commenting out the password check portion of the query",
    },
    {
      title: "3. UNION Attack (All Users)",
      value: "' OR 1=1 UNION SELECT * FROM users WHERE '1'='1",
      description:
        "Returns ALL users from the database by using UNION to append a second query",
    },
    {
      title: "4. Multiple OR Conditions",
      value: "' OR 1=1 OR '1'='",
      description:
        "Uses redundant OR conditions to ensure the WHERE clause evaluates to true",
    },
    {
      title: "5. Numerical Comparison",
      value: "x' OR 1=1--",
      description:
        "Uses a numerical comparison (1=1) that's always true rather than string comparison",
    },
    {
      title: "6. Authentication Bypass with NULL",
      value: "admin' OR username IS NOT NULL--",
      description:
        "Checks for any non-NULL username, which will match all user records",
    },
    {
      title: "7. Batch Query Injection",
      value:
        "admin'; INSERT INTO users VALUES (99, 'hacker', 'pass', 'hack@er.com');--",
      description:
        "Attempts to execute multiple SQL statements by adding a semicolon and new command",
    },
    {
      title: "8. Case Manipulation",
      value: "aDmIn'/**/Or/**/1=1--",
      description:
        "Uses case variation and SQL comments to evade simple detection filters",
    },
    {
      title: "9. UNION with Custom Values",
      value: "' UNION SELECT 1, 'admin', 'password123', 'admin@example.com'--",
      description:
        "Creates a fake user record through a UNION attack with specified column values",
    },
    {
      title: "10. OR with Subquery",
      value: "' OR EXISTS(SELECT * FROM users)--",
      description:
        "Uses a subquery that will be true if the users table has any records at all",
    },
  ];
```

### SQL Injection Prevention
The secure login implementation demonstrates several security layers:
```javascript
export const secureLogin = (req, res) => {
  // Extract username and password from request body
  let { username, password } = req.body;
```

#### 1. Basic validation - check if username and password are provided.
```javascript
if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }
```
  
#### 2. Input Validation - checks for required fields such as:
- Length validation
```javascript
 if (username.length > 12 || password.length > 12) {
    return res.status(400).json({ 
      message: 'Input length exceeds maximum allowed characters' 
    });
  }
```
- Disallow spaces in username or password
```javascript
if (username.includes(' ') || password.includes(' ') ) {
    return res.status(400).json({ 
      message: 'Username or Password cannot contain spaces' 
    });
  }
```
- Check for SQL keywords in username
```javascript
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
```

#### 3. Parameterized Queries
The most important protection is the use of parameterized queries (prepared statements) which separate SQL code from user data.
```javascript
const query = 'SELECT * FROM users WHERE username = ?';

  // Execute the secure query with parameters
  db.get(query, [username], (err, user) => {
    if (err) {
      // If there's a database error, log it but don't expose details to client
      return res.status(500).json({ message: 'Database error occurred' });
    }

    // rest of function...
  });
};
```
With this approach, the database treats user input strictly as data, not as executable code, regardless of what characters it contains.

#### 4. Password Hashing
Passwords are never stored in plain text. Instead, they are hashed using bcrypt.
```javascript
const passwordMatch = bcrypt.compareSync(password, user.password);
```
```javascript
const hashPassword = (password) => bcrypt.hashSync(password, 10)
```

#### 5. Error messages are generic to avoid information leakage

## Project Structure

```
project-root/
├── frontend/               # React frontend application
│   ├── src/
│   │   ├── components/     # React components
│   │   │   ├── Header.jsx              # Navigation header
│   │   │   ├── VulnerableLogin.jsx     # Demonstrates vulnerable login
│   │   │   └── SecureLogin.jsx         # Demonstrates secure login
│   │   ├── App.jsx         # Main application component
│   │   └── main.jsx        # Application entry point
│   ├── public/             # Static files
│   └── index.html          # HTML template
│
├── backend/                # Node.js/Express backend
│   ├── src/
│   │   ├── controllers/    # Request handlers
│   │   │   └── auth.controller.js      # Authentication logic
│   │   ├── routes/         # API routes
│   │   │   └── auth.routes.js          # Authentication routes
│   │   ├── db/             # Database setup
│   │   │   └── database.js             # SQLite configuration
│   │   └── index.js        # Server entry point
│   └── .env                # Environment variables
```

## Setup and Installation

### Prerequisites

- Node.js (v14.x or later)
- npm or yarn

### Installation Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/sql-injection-demo.git
   cd sql-injection-demo
   ```

2. Install backend dependencies:
   ```
   cd backend
   npm install
   ```

3. Install frontend dependencies:
   ```
   cd ../frontend
   npm install
   ```

4. Start the backend server:
   ```
   cd ../backend
   npm run dev
   ```

5. Start the frontend development server:
   ```
   cd ../frontend
   npm run dev
   ```

6. Open your browser and navigate to `http://localhost:5173`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

