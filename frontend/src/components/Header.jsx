import { Link, useLocation } from 'react-router-dom'

const Header = () => {
  // useLocation hook gives us information about the current URL
  const location = useLocation()
  
  return (
    // The header component wraps our navigation bar
    <header className="navbar bg-base-200 shadow-md">
      {/* The left section of our navbar */}
      <div className="navbar-start">
        {/* Mobile hamburger menu - only shows on small screens*/}
        <div className="dropdown">
          {/* The hamburger button that toggles the mobile menu tabIndex makes it focusable with keyboard navigation*/}
          <label tabIndex={0} className="btn btn-ghost lg:hidden">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h8m-8 6h16" />
            </svg>
          </label>
          
          {/* Dropdown menu that appears on mobile when hamburger is clicked*/}
          <ul tabIndex={0} className="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-base-100 rounded-box w-52">
            {/* Navigation links for mobile view */}
            <li><Link to="/" className={location.pathname === '/' ? 'active' : ''}>Home</Link></li>
            <li><Link to="/vulnerable" className={location.pathname === '/vulnerable' ? 'active' : ''}>Vulnerable Login</Link></li>
            <li><Link to="/secure" className={location.pathname === '/secure' ? 'active' : ''}>Secure Login</Link></li>
          </ul>
        </div>
        
        {/* App logo/title that links to home page*/}
        <Link to="/" className="btn btn-ghost normal-case text-xl">SQL Injection Demo</Link>
      </div>
      
      {/* Center section of navbar - contains horizontally arranged links Only visible on larger screens (lg:flex)*/}
      <div className="navbar-center hidden lg:flex">
        <ul className="menu menu-horizontal px-1">

          {/* Navigation links for desktop view Each link checks against current location to highlight active page*/}
          <li><Link to="/" className={location.pathname === '/' ? 'active' : ''}>Home</Link></li>
          <li><Link to="/vulnerable" className={location.pathname === '/vulnerable' ? 'active' : ''}>Vulnerable Login</Link></li>
          <li><Link to="/secure" className={location.pathname === '/secure' ? 'active' : ''}>Secure Login</Link></li>
        </ul>
      </div>
      
    </header>
  )
}

export default Header