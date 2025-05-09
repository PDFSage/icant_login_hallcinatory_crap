// frontend/src/App.js
import React from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Login from './components/Login'
import Graph from './components/Graph'
export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/graph" element={<Graph />} />
        <Route path="*" element={<Navigate to="/login" />} />
      </Routes>
    </Router>
  )
}