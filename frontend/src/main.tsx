import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import ErrorBoundary from './components/ErrorBoundary'
import './index.css'

// Clean up any stale auth storage from old key
localStorage.removeItem('auth-storage')

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      {/* 
        React Router v7 future flags:
        - v7_startTransition: Wraps state updates in React.startTransition for better concurrent rendering
        - v7_relativeSplatPath: Changes relative path resolution in splat routes
        These flags opt-in to v7 behavior for smoother migration when v7 releases.
      */}
      <BrowserRouter
        future={{
          v7_startTransition: true,
          v7_relativeSplatPath: true,
        }}
      >
        <App />
      </BrowserRouter>
    </ErrorBoundary>
  </React.StrictMode>,
)
