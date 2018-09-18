const forge = require('./lib')
const fs = require('fs')
const net = require('net')

// forge.options.usePureJavaScript = true
var socket = new net.Socket()
console.log(forge.tls.Version)

const print = data => {
  let buffer = Buffer.from(data, 'binary')

  console.log(buffer.length)

  while (buffer.length > 32) {
    console.log(buffer.slice(0, 32))
    buffer = buffer.slice(32)
    
  }

  if (buffer.length)
    console.log(buffer)
}

var client = forge.tls.createConnection({
  server: false,
  caStore: [fs.readFileSync('ca.pem').toString()],
  cipherSuites: [
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
  verify: function (connection, verified, depth, certs) {
    // skip verification for testing
    console.log('[tls] server certificate verified')
    return true
  },
  // virtualHost: 'x-amzn-mqtt-ca',
  // ALPN: 'x-amzn-mqtt-ca',
  getPrivateKey: function (connection, cert) {
    return fs.readFileSync('deviceCert.key').toString()
  },
  getCertificate: (connection, hint) => {
    return fs.readFileSync('deviceCert.crt').toString()
  },
  connected: function (connection) {
    console.log('[tls] connected')
    // prepare some data to send (note that the string is interpreted as
    // 'binary' encoded, which works for HTTP which only uses ASCII, use
    // forge.util.encodeUtf8(str) otherwise
    // client.prepare('GET / HTTP/2.0\r\n\r\n')
  },
  tlsDataReady: function (connection) {
    // encrypted data is ready to be sent to the server
    var data = connection.tlsData.getBytes()

    console.log('data length', data.length)

//    print(data)

    socket.write(data, 'binary') // encoding should be 'binary'
  },
  dataReady: function (connection) {
    // clear data from the server is ready
    var data = connection.data.getBytes()
    console.log('[tls] data received from the server: ' + data)
  },
  closed: function () {
    console.log('[tls] disconnected')
  },
  error: function (connection, error) {
    console.log('[tls] error', error)
  }
})

socket.on('connect', function () {
  console.log('[socket] connected')
  client.handshake()
})
socket.on('data', function (data) {
  // console.log('server data:', data.toString(), '  //')
  client.process(data.toString('binary')) // encoding should be 'binary'
})
socket.on('end', function () {
  console.log('[socket] disconnected')
})

// connect to google.com
socket.connect(8883, 'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn')
