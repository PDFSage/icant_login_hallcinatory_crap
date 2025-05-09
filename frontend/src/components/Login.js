// frontend/src/components/Login.js
import React, { useState } from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'
export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const navigate = useNavigate()
  const handleSubmit = async e => {
    e.preventDefault()
    try {
      await axios.post('/api/login', { username, password }, { withCredentials: true })
      navigate('/graph')
    } catch {
      alert('Login failed')
    }
  }
  return (
    <form onSubmit={handleSubmit}>
      <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" />
      <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" />
      <button type="submit">Login</button>
    </form>
  )
}