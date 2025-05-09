// frontend/src/components/Graph.js
import React, { useEffect, useState } from 'react'
export default function Graph() {
  const [html, setHtml] = useState('')
  useEffect(() => {
    fetch('/api/graph', { credentials: 'include' })
      .then(res => res.text())
      .then(setHtml)
  }, [])
  return <div dangerouslySetInnerHTML={{ __html: html }} />
}