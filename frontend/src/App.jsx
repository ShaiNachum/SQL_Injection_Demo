import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
// Router: Creates the routing context for the app - like the road system for navigation
// Routes: A container for all our Route components - like a map showing all possible destinations
// Route: Defines a path and what component to show at that path - like an address that leads to a specific location

import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import Header from './components/Header'
import VulnerableLogin from './components/VulnerableLogin'
import SecureLogin from './components/SecureLogin'

// HomePage component - this is our landing page
function HomePage() {
  return (
    <div className="container mx-auto px-4 py-8">
      {/* Main card container */}
      <div className="card bg-base-100 shadow-xl">
        <div className="card-body">
          {/* Main title */}
          <h1 className="card-title text-3xl mb-6">SQL Injection Demonstration</h1>
          
          {/* What is SQL Injection section */}
          {/* Like an educational poster explaining a concept */}
          <h2 className="text-2xl font-bold mb-4">What is SQL Injection?</h2>
          <p className="mb-4">
            SQL Injection is a code injection technique that exploits vulnerabilities in applications 
            that interact with databases. It occurs when user input is incorrectly filtered and directly
            included in SQL queries, allowing attackers to manipulate database queries.
          </p>
          
          {/* Divider line */}
          <div className="divider"></div>
          
          {/* Demonstration overview section */}
          <h2 className="text-2xl font-bold mb-4">Demonstration Overview</h2>
          <p className="mb-4">This application includes two login forms:</p>
          
          {/* Cards explaining the two different login forms */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            {/* Vulnerable login card */}
            <div className="card bg-red-50 shadow-sm">
              <div className="card-body">
                <h3 className="card-title text-red-700">Vulnerable Login</h3>
                <p>Demonstrates a login form vulnerable to SQL injection attacks.</p>
                <div className="card-actions justify-end">
                  <a href="/vulnerable" className="btn btn-sm btn-error">Try Vulnerable Login</a>
                </div>
              </div>
            </div>
            
            {/* Secure login card */}
            <div className="card bg-green-50 shadow-sm">
              <div className="card-body">
                <h3 className="card-title text-green-700">Secure Login</h3>
                <p>Demonstrates a properly implemented login form that prevents SQL injection.</p>
                <div className="card-actions justify-end">
                  <a href="/secure" className="btn btn-sm btn-success">Try Secure Login</a>
                </div>
              </div>
            </div>
          </div>
          
          {/* Divider line */}
          <div className="divider"></div>
          
          {/* Sample credentials section */}
          <h2 className="text-2xl font-bold mb-4">Sample Credentials</h2>
          <p className="mb-4">You can use these credentials with the secure login (they won't work with SQL injection):</p>
          
          {/* Table of sample user credentials */}
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Password</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>admin</td>
                  <td>admin123</td>
                </tr>
                <tr>
                  <td>user1</td>
                  <td>password123</td>
                </tr>
                <tr>
                  <td>securityuser</td>
                  <td>secure456</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}

// App component - the main component that renders everything
function App() {
  return (
    // Router wraps our entire application to enable navigation
    <Router>
      {/* Main container with theme settings */}
      <div className="min-h-screen bg-base-200" data-theme="corporate">
        {/* Header is always visible, regardless of which page we're on */}
        <Header />
        
        {/* Main content area where pages are rendered */}
        <main className="container mx-auto px-4 py-8">
          {/* Routes define what components to show at different paths */}
          <Routes>
            {/* Home page route - shown at the root URL */}
            <Route path="/" element={<HomePage />} />
            
            {/* Vulnerable login page route */}
            <Route path="/vulnerable" element={<VulnerableLogin />} />
            
            {/* Secure login page route */}
            <Route path="/secure" element={<SecureLogin />} />
          </Routes>
        </main>
        
        {/* ToastContainer for showing notifications */}
        <ToastContainer position="bottom-right" />
      </div>
    </Router>
  )
}

// Export the App component so it can be imported in main.jsx
export default App