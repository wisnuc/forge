const fs = require('fs')
const crypto = require('crypto')

const publicKey = fs.readFileSync('public.key')

let text = 'hello world'

for (let i = 0; i < 5; i++) {
  let encrypted = crypto.publicEncrypt(publicKey, Buffer.from(text))
  console.log(encrypted)
}

