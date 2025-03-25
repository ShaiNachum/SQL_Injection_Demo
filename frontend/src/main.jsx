import React from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

// Create a root for our React application in the DOM element with id "root"
const root = createRoot(document.getElementById('root'))

// Render our application inside React's StrictMode
// StrictMode - helps catch potential problems
// The entire application (App) is rendered within this environment
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)