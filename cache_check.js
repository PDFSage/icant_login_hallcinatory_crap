const https=require('https')
const url="https://nsa.gov"
https.get(url,res=>console.log(res.headers['cache-control']||'no-cache-control'))
