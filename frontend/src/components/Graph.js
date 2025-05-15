/* frontend/src/components/Graph.js */
import React from 'react'
export default function Graph() {
  return (
    <iframe
      src="/api/graph"
      style={{width: '100%', height: '600px'}}
      title="Global Graph"
    />
  )
}