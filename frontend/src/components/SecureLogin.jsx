import { useState } from 'react'  
import axios from 'axios'         
import { toast } from 'react-toastify' 

const API_URL = 'http://localhost:5000/api/auth'

const SecureLogin = () => {
  // State variables to manage component data
  const [username, setUsername] = useState('') // Stores what the user types in the username field
  const [password, setPassword] = useState('') // Stores what the user types in the password field
  const [loading, setLoading] = useState(false) // Keeps track of whether we're waiting for a response
  const [result, setResult] = useState(null) // Stores the result after we attempt to log in
  const [secureQuery, setSecureQuery] = useState('') // Stores the secure SQL query for display purposes

  // Function that runs when the user submits the login form
  const handleSecureLogin = async (e) => {
    // Prevent the browser from refreshing the page when the form is submitted
    e.preventDefault()
    
    setLoading(true)
    
    // Clear any previous results
    setResult(null)
    
    try {
      // Show a demonstration of the parameterized query 
      // This is a visual aid showing how the secure query is structured
      setSecureQuery(`SELECT * FROM users WHERE username = ? /* First parameter: ${username} */`)
      
      // Send the login request to the secure endpoint
      const response = await axios.post(`${API_URL}/secure/login`, { username, password })
      
      // If the request succeeds (no error was thrown), set the result to success
      setResult({
        success: true,
        message: 'Login successful! (Secure authentication)',
        data: response.data
      })
      
      // Show a success notification
      toast.success('Secure login successful!')

    } catch (error) {
      // If there was an error, store the error information
      setResult({
        success: false,
        message: error.response?.data?.message || 'Login failed',
        error: error.response?.data || error.message
      })
      
      // Show an error notification
      toast.error('Login failed')

    } finally {
      // Whether the login succeeded or failed, we're no longer loading
      setLoading(false)
    }
  }

  // Example SQL injection attacks users can try - same as in VulnerableLogin
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

  // Function to apply an example to the username field
  const applyExample = (example) => {
    setUsername(example.value);
    setPassword("anything"); // The password doesn't matter for these attacks
  }

  // The JSX that renders our component's user interface
  return (
    // Main container with special styling for the secure section
    <div className="secure-section p-6 rounded-lg">
      {/* Section title */}
      <h2 className="text-2xl font-bold mb-4">Secure Login Form</h2>
      
      {/* Success alert to indicate this is the secure implementation */}
      <div className="alert alert-success mb-4">
        <svg xmlns="http://www.w3.org/2000/svg" className="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <div>
          <h3 className="font-bold">This login form is protected against SQL injection!</h3>
          <p className="text-sm">It demonstrates the proper way to implement authentication.</p>
        </div>
      </div>

      {/* Login form */}
      <form onSubmit={handleSecureLogin} className="space-y-4 mb-6">
        {/* Username input field */}
        <div className="form-control">
          <label className="label mr-4">
            <span className="label-text">Username</span>
          </label>
          <input 
            type="text" 
            className="input input-bordered" 
            value={username}
            onChange={(e) => setUsername(e.target.value)} // Update state when the input changes
            placeholder="Username (try the same injection!)"
            required
          />
        </div>
        
        {/* Password input field */}
        <div className="form-control">
          <label className="label mr-4">
            <span className="label-text">Password</span>
          </label>
          <input 
            type="password" 
            className="input input-bordered" 
            value={password}
            onChange={(e) => setPassword(e.target.value)} // Update state when the input changes
            placeholder="Password"
            required
          />
        </div>
        
        {/* Submit button - shows a spinner when loading */}
        <button 
          type="submit" 
          className="btn btn-primary w-full"
          disabled={loading} // Prevent multiple submissions while processing
        >
          {loading ? <span className="loading loading-spinner"></span> : 'Login (Secure)'}
        </button>
      </form>

      {/* Divider line with text */}
      <div className="divider">SQL Injection Examples to Try</div>
      
      {/* Grid of example SQL injections users can try */}
      <div className="h-64 overflow-y-auto pr-2">
        <div className="grid grid-cols-1 gap-4">
          {examples.map((example, index) => (
            <div key={index} className="card bg-base-200 shadow-sm">
              <div className="card-body p-4">
                <h3 className="card-title text-base">{example.title}</h3>
                <div className="code-block text-sm bg-base-300 p-2 rounded my-2 overflow-x-auto text-black">
                  {example.value}
                </div>
                <p className="text-xs">{example.description}</p>
                <button
                  className="btn btn-sm btn-outline mt-2"
                  onClick={() => applyExample(example)}
                >
                  Apply Example
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Display the secure parameterized query if available */}
      {secureQuery && (
        <div className="mb-6">
          <h3 className="text-lg font-semibold mb-2">Parameterized SQL Query:</h3>
          <pre className="code-block p-3 bg-base-300 rounded overflow-x-auto">
            <code className="text-gray-900" dangerouslySetInnerHTML={{
              __html: secureQuery.replace(
                /(SELECT|FROM|WHERE|AND|OR|UNION|=|\?|\/\*.*\*\/)/g, 
                (match) => {
                  if (match.startsWith('/*')) return `<span class="text-green-600">${match}</span>`;
                  if (match === '?') return `<span class="highlight">${match}</span>`;
                  if (match === '=') return `<span class="sql-operator">${match}</span>`;
                  return `<span class="sql-keyword">${match}</span>`;
                }
              )
            }} />
          </pre>
        </div>
      )}

      {/* Display the result of the login attempt if available */}
      {result && (
        <div className={`alert ${result.success ? 'alert-success' : 'alert-error'} mt-4`}>
          <div>
            <h3 className="font-bold">{result.success ? 'Success!' : 'Failed!'}</h3>
            <div className="text-sm">{result.message}</div>
            
            {/* If login succeeded, show the user data that was retrieved */}
            {result.success && result.data && (
              <div className="mt-2 p-2 bg-base-100 rounded">
                <div className="text-xs font-semibold">User data retrieved:</div>
                <pre className="text-xs overflow-x-auto">{JSON.stringify(result.data.user, null, 2)}</pre>
              </div>
            )}
            
            {/* If login failed, show the error details */}
            {!result.success && result.error && (
              <div className="mt-2 p-2 bg-base-100 rounded">
                <pre className="text-xs overflow-x-auto">{JSON.stringify(result.error, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Educational section explaining the security measures */}
      <div className="mt-8">
        <h3 className="text-lg font-semibold mb-2">Why This Is Secure</h3>
        <p className="mb-4">
          This login form is protected against SQL injection because it uses parameterized queries.
          The key security features include:
        </p>
        <ul className="list-disc list-inside space-y-2 mb-4">
          <li><strong>Parameterized queries</strong> - User input is passed separately from the SQL query structure</li>
          <li><strong>Prepared statements</strong> - The database treats parameters as data, not as part of the SQL command</li>
          <li><strong>Input validation</strong> - Rejects input containing SQL keywords and suspicious characters</li>
          <li><strong>Password hashing</strong> - Passwords are never stored in plain text</li>
        </ul>
        <p className="mb-4">
          When you try the same SQL injection attacks, they'll be treated as literal strings rather than SQL code,
          or will be rejected outright by validation checks. This demonstrates why proper input handling is essential
          for secure web applications.
        </p>
      </div>
    </div>
  )
}

// Export the component so it can be imported elsewhere
export default SecureLogin