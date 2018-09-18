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
  if (body.readUInt16BE(0) !== 0x0303) throw new Error('unsupported tls version')

  body = body.slice(2) 

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

module.exports = {
  ClientHello,
  handleServerHello,
}
