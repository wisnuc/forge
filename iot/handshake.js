const fs = require('fs')
const child = require('child_process')
const crypto = require('crypto')

const PRF = require('./prf')

const HandshakeMessage = (type, message) =>
  Buffer.concat([
    Buffer.from([
      type,
      (message.length >> 16) & 0xff,
      (message.length >> 8) & 0xff,
      message.length & 0xff
    ]), 
    message
  ]) 

const ClientHello = random => {

  // TLS 1.2
  let client_version = Buffer.from([0x03, 0x03])

  // time + random bytes
/**
  clientHelloRandom = Buffer.alloc(32)
  crypto.randomFillSync(clientHelloRandom)
  clientHelloRandom.writeUInt32BE(Math.floor(new Date().getTime() / 1000))
*/

  // session id length = 0
  let session_id = Buffer.from([0x00])

  /**
    CipherSuite TLS_RSA_WITH_NULL_MD5                 = { 0x00,0x01 };
    CipherSuite TLS_RSA_WITH_NULL_SHA                 = { 0x00,0x02 };
    CipherSuite TLS_RSA_WITH_NULL_SHA256              = { 0x00,0x3B };
    CipherSuite TLS_RSA_WITH_RC4_128_MD5              = { 0x00,0x04 };
    CipherSuite TLS_RSA_WITH_RC4_128_SHA              = { 0x00,0x05 };
    CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA         = { 0x00,0x0A };
  * CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA          = { 0x00,0x2F };
    CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA          = { 0x00,0x35 };
    CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256       = { 0x00,0x3C };
    CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256       = { 0x00,0x3D };

  * mandatory
  */
  let cipher_suites = Buffer.from([0x00, 0x04, 0x00, 0x2f, 0x00, 0x35])

  // no compression
  let compression_methods = Buffer.from([0x01, 0x00])
  let extensions = Buffer.from([
    0x00, 0x0a, // Extensions Length: 10
      0x00, 0x0d, // type: signature_algorithms
      0x00, 0x06, // length: 6
        0x00, 0x04, // Signature Hash Algorithms Length: 4 
          0x04, 0x01, // sha256, rsa
          0x02, 0x01, // sha1, rsa
  ])

  let payload = Buffer.concat([
    client_version,
    random,
    session_id,
    cipher_suites,
    compression_methods,
    extensions
  ])

  return HandshakeMessage(0x01, payload)
}

const handleServerHello = message => {
  if (message.length < 4) throw new Error('invalid message length')
  if (message[0] !== 0x02) throw new Error('not a server hello message')

  let length = message.readUInt32BE(0) & 0x00ffffff
  let body = message.slice(4)

  if (length !== body.length) throw new Error('invalid message body length')

  let version = body.readUInt16BE(0)
  body = body.slice(2) 

  if (version !== 0x0303) throw new Error('unsupported tls version')

  let random = body.slice(0, 32)
  body = body.slice(32)

  // TODO is session Id fixed length ? 
  let sessionIdLength = body[0]
  body = body.slice(1)
  
  let sessionId = body.slice(0, sessionIdLength)
  body = body.slice(sessionIdLength)

  let cipherSuite = body.readUInt16BE(0)
  body = body.slice(2)
  if (cipherSuite !== 0x002f) throw new Error('unsupported cipher suite')

  let compression = body[0]
  body = body.slice(1)
  if (compression !== 0) throw new Error('unsupported compression')

  if (body.length !== 0) console.log('WARNING: extra data in server hello message') 

  return { random, sessionId }
}

const handleServerCertificate = message => {
  if (message.length < 4) throw new Error('invalid message length')
  if (message[0] !== 0x0b) throw new Error('not a cerificate message')

  let length = message.readUInt32BE(0) & 0x00ffffff  
  let body = message.slice(4)
  if (length !== body.length) throw new Error('invalid message body length')
 
  let certsLength = body[0] * 65536 + body[1] * 256 + body[2]  
  // drop everything after certs
  body = body.slice(3, 3 + certsLength)

  let certs = [] 
  while (body.length) {
    // TODO validate body.length and certLen
    let certLen = body[0] * 65536 + body[1] * 256 + body[2]
    certs.push(body.slice(3, 3 + certLen))
    body = body.slice(3 + certLen)
  }

  let input = certs[0]
  let publicKey = child.execSync('openssl x509 -inform der -noout -pubkey', { input })
  return { publicKey, certs }
}

const handleCertificateRequest = message => {
  if (message.length < 4) throw new Error('invalid message length')
  if (message[0] !== 0x0d) throw new Error('not a cerificate request message')

  let length = message.readUInt32BE(0) & 0x00ffffff  
  let body = message.slice(4)
  if (length !== body.length) throw new Error('invalid message body length')

  console.log('   do nothing') 
}

const handleServerHelloDone = message => {
  if (message.length < 4) throw new Error('invalid message length')
  if (message[0] !== 0x0e) throw new Error('not a server hello done message')

  let length = message.readUInt32BE(0) & 0x00ffffff  
  let body = message.slice(4)
  if (length !== body.length) throw new Error('invalid message body length')

  console.log('   do nothing')
}

const ClientCertificate = () => {
  // convert pem crt to der
  let certString = fs.readFileSync('deviceCert.crt')
    .toString()
    .split('\n')
    .filter(x => !!x && !x.startsWith('--'))
    .join('')

  let cert = Buffer.from(certString, 'base64')
  let certLen = Buffer.from([
    cert.length >> 16,
    cert.length >> 8,
    cert.length
  ])

  let certsLen = Buffer.from([
    (cert.length + 3) >> 16,
    (cert.length + 3) >> 8,
    (cert.length + 3)
  ])

  let payload = Buffer.concat([certsLen, certLen, cert])
  return HandshakeMessage(0x0b, payload)
}

const ClientKeyExchange = (publicKey, preMasterSecret) => {

/**
    preMasterSecret = Buffer.alloc(48)
    crypto.randomFillSync(preMasterSecret, 48)
    preMasterSecret[0] = 0x03
    preMasterSecret[1] = 0x03
*/

  let encrypted = crypto.publicEncrypt(publicKey, preMasterSecret)
  let len16 = Buffer.from([encrypted.length >> 8, encrypted.length])
  let payload = Buffer.concat([len16, encrypted])
  return HandshakeMessage(0x10, payload)
}

const CertificateVerify = tbs => {
  let sigAlgorithm = Buffer.from([0x04, 0x01])
  let sigLength = Buffer.from([0x00, 0x00])
  let privateKey = fs.readFileSync('deviceCert.key')
  let sign = crypto.createSign('sha256')
  sign.update(tbs)
  let sig = sign.sign(privateKey)
  sigLength.writeUInt16BE(sig.length)
  return HandshakeMessage(0x0f, Buffer.concat([sigAlgorithm, sigLength, sig]))
}

const ChangeCipherSpecMessage = () =>
  Buffer.from([
    0x14, // type
    0x03, 0x03, // version
    0x00, 0x01, // length
    0x01 // content
  ])

const deriveKeys = (preMasterSecret, clientRandom, serverRandom) => {
  let random

  // when generating master secret, client random first
  random = Buffer.concat([clientRandom, serverRandom])
  masterSecret = PRF(preMasterSecret, 'master secret', random, 48, 'sha256')

  // when extracting keys, server random first
  random = Buffer.concat([serverRandom, clientRandom])
  let keys = PRF(masterSecret, 'key expansion', random, 2 * (20 + 16), 'sha256')

  return {
    masterSecret,
    clientWriteMacKey: keys.slice(0, 20),
    serverWriteMacKey: keys.slice(20, 40),
    clientWriteKey: keys.slice(40, 56),
    serverWriteKey:keys.slice(56, 72),
  }
}

const ClientFinished = (masterSecret, handshakeMessages) => {
  let verifyData = PRF( masterSecret, 'client finished',
    crypto.createHash('sha256').update(handshakeMessages).digest(),
    12, 'sha256')
  
  return HandshakeMessage(0x14, verifyData)
}



module.exports = {
  ClientHello,
  handleServerHello,
  handleServerCertificate,
  handleCertificateRequest,
  handleServerHelloDone,
  ClientCertificate,
  ClientKeyExchange,
  CertificateVerify,
  ClientFinished,
  deriveKeys
}
