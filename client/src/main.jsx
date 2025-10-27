import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import './index.css'; // Optional: for basic styling

// Get the root element from your index.html
const rootElement = document.getElementById('root');
const root = ReactDOM.createRoot(rootElement);

// Render your app
root.render(
  <React.StrictMode>
    {/*
      Wrap your <App /> component with <BrowserRouter>.
      This provides the routing context to all components inside App.
    */}
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);