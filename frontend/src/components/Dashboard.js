// frontend/src/components/Dashboard.js
import React, { useEffect, useState } from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'

export default function Dashboard() {
  const navigate = useNavigate()
  const [docs, setDocs] = useState([])
  const [file, setFile] = useState(null)
  const [isAdmin, setIsAdmin] = useState(false)
  const [risk, setRisk] = useState({})
  const [credentials, setCredentials] = useState([])
  const [credType, setCredType] = useState('')
  const [credValue, setCredValue] = useState('')

  const handleLogout = async () => {
    await axios.post('/api/logout', {}, { withCredentials: true })
    navigate('/login')
  }

  const getDocs = async () => {
    const res = await axios.get('/api/docs', { withCredentials: true })
    setDocs(res.data.docs)
  }

  const uploadFile = async e => {
    e.preventDefault()
    if (!file) return
    const formData = new FormData()
    formData.append('file', file)
    try {
      await axios.post('/api/upload', formData, { withCredentials: true })
      getDocs()
    } catch {
      alert('Upload failed')
    }
  }

  const getLeakRisk = async () => {
    try {
      const res = await axios.get('/api/leak_risk', { withCredentials: true })
      setRisk(res.data.risk || {})
    } catch {}
  }

  const checkAdmin = async () => {
    try {
      const r = await axios.get('/api/leak_risk', { withCredentials: true })
      if (r.data && r.data.risk) {
        setIsAdmin(true)
        setRisk(r.data.risk)
      }
    } catch {
      setIsAdmin(false)
    }
  }

  const getCredentialsList = async () => {
    try {
      const r = await axios.get('/api/get_credentials', { withCredentials: true })
      setCredentials(r.data.credentials || [])
    } catch {}
  }

  const addCredential = async e => {
    e.preventDefault()
    try {
      await axios.post('/api/add_credential', { type: credType, value: credValue }, { withCredentials: true })
      setCredType('')
      setCredValue('')
      getCredentialsList()
    } catch {}
  }

  useEffect(() => {
    (async () => {
      await axios.get('/api/graph', { credentials: 'include' })
    })()
    getDocs()
    checkAdmin()
    getCredentialsList()
  }, [])

  return (
    <div className="dashboard-container">
      <h1>Federal Top Secret Dashboard</h1>
      <button onClick={() => navigate('/graph')}>View Global Graph</button>
      <button onClick={handleLogout}>Logout</button>
      {isAdmin && (
        <>
          <hr/>
          <h2>Leak Risk Prediction</h2>
          <button onClick={getLeakRisk}>Refresh Risk</button>
          <ul>
            {Object.keys(risk).map(u => (
              <li key={u}>{u}: {risk[u].toFixed(3)}</li>
            ))}
          </ul>
        </>
      )}
      <hr/>
      <form onSubmit={uploadFile}>
        <h2>Upload Document</h2>
        <input type="file" onChange={e => setFile(e.target.files[0])} />
        <button type="submit">Upload</button>
      </form>
      <div className="docs-list">
        <h2>Documents</h2>
        {docs.map(d => <div key={d.id}>{d.filename} (uploader: {d.uploader})</div>)}
      </div>
      <hr/>
      <div>
        <h2>Credentials Manager</h2>
        <form onSubmit={addCredential}>
          <input placeholder="Type" value={credType} onChange={e => setCredType(e.target.value)} />
          <input placeholder="Value" value={credValue} onChange={e => setCredValue(e.target.value)} />
          <button type="submit">Add</button>
        </form>
        <div className="credentials-list">
          <h3>Your Credentials</h3>
          {credentials.map(c => (
            <div key={c.id}>
              {c.type}: {c.value}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}