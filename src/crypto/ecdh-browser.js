'use strict'

const crypto = require('./webcrypto')()
var elliptic = self.elliptic
const nodeify = require('nodeify')
const BN = require('asn1.js').bignum
const Buffer = require('safe-buffer').Buffer

const util = require('./util')
const toBase64 = util.toBase64
const toBn = util.toBn

const bits = {
  'P-256': 256,
  'P-384': 384,
  'P-521': 521
}

const curveMap = {
  'P-256': 'p256',
  'P-384': 'p384',
  'P-521': 'p521'
}

function nCryptoGenerateEphmeralKeyPair(curveName, callback) {
  if (!elliptic) {
    throw(new Error('elliptic must exist in global namespace'))
    // elliptic = require('elliptic')
  }
  const EC = elliptic.ec
  const curve = curveMap[curveName]
  if (!curve) {
    throw new Error('unsupported curve passed')
  }
  const ec = new EC(curve)
  const priv = ec.genKeyPair()

  const genSharedKey = (theirPub, forcePrivate, cb) => {
    if (typeof forcePrivate === 'function') {
        cb = forcePrivate
        forcePrivate = undefined
    }
    var a = unmarshalPublicKey(curveName, theirPub)
    var bnobj = {
      x: toBn(a.x),
      y: toBn(a.y)
    }
    const pub = ec.keyFromPublic(bnobj)
    var p = priv
    if (forcePrivate) {
      console.log(unmarshalPrivateKey(curveName, forcePrivate));
      var privhex = Buffer.from(unmarshalPrivateKey(curveName, forcePrivate).d, 'base64').toString('hex')
      p = ec.keyFromPrivate(privhex)
    }
    cb(null, p.derive(pub.getPublic()).toArrayLike(Buffer, 'be'))
  }
  var a = priv.getPublic()
  var jwk = {}
  jwk.x = a.getX()
  jwk.y = a.getY()
  jwk.crv = curveName
  callback(null, {
    key: marshalBNPublicKey(jwk),
    genSharedKey
  })
}

exports.generateEphmeralKeyPair = function (curve, callback) {
  if (!crypto) {
    return nCryptoGenerateEphmeralKeyPair(curve, callback)
  }
  nodeify(crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: curve
    },
    true,
    ['deriveBits']
  ).then((pair) => {
    // forcePrivate is used for testing only
    const genSharedKey = (theirPub, forcePrivate, cb) => {
      if (typeof forcePrivate === 'function') {
        cb = forcePrivate
        forcePrivate = undefined
      }

      let privateKey

      if (forcePrivate) {
        privateKey = crypto.subtle.importKey(
          'jwk',
          unmarshalPrivateKey(curve, forcePrivate),
          {
            name: 'ECDH',
            namedCurve: curve
          },
          false,
          ['deriveBits']
        )
      } else {
        privateKey = Promise.resolve(pair.privateKey)
      }

      const keys = Promise.all([
        crypto.subtle.importKey(
          'jwk',
          unmarshalPublicKey(curve, theirPub),
          {
            name: 'ECDH',
            namedCurve: curve
          },
          false,
          []
        ),
        privateKey
      ])

      nodeify(keys.then((keys) => crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          namedCurve: curve,
          public: keys[0]
        },
        keys[1],
        bits[curve]
      )).then((bits) => Buffer.from(bits)), cb)
    }

    return crypto.subtle.exportKey(
      'jwk',
      pair.publicKey
    ).then((publicKey) => {
      return {
        key: marshalPublicKey(publicKey),
        genSharedKey
      }
    })
  }), callback)
}

const curveLengths = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66
}

// Marshal converts a jwk encodec ECDH public key into the
// form specified in section 4.3.6 of ANSI X9.62. (This is the format
// go-ipfs uses)
function marshalPublicKey (jwk) {
  const byteLen = curveLengths[jwk.crv]

  return Buffer.concat([
    Buffer.from([4]), // uncompressed point
    toBn(jwk.x).toArrayLike(Buffer, 'be', byteLen),
    toBn(jwk.y).toArrayLike(Buffer, 'be', byteLen)
  ], 1 + byteLen * 2)
}

function marshalBNPublicKey (jwk) {
  const byteLen = curveLengths[jwk.crv]

  return Buffer.concat([
    Buffer.from([4]), // uncompressed point
    jwk.x.toArrayLike(Buffer, 'be', byteLen),
    jwk.y.toArrayLike(Buffer, 'be', byteLen)
  ], 1 + byteLen * 2)
}

// Unmarshal converts a point, serialized by Marshal, into an jwk encoded key
function unmarshalPublicKey (curve, key) {
  const byteLen = curveLengths[curve]

  if (!key.slice(0, 1).equals(Buffer.from([4]))) {
    throw new Error('Invalid key format')
  }
  const x = new BN(key.slice(1, byteLen + 1))
  const y = new BN(key.slice(1 + byteLen))

  return {
    kty: 'EC',
    crv: curve,
    x: toBase64(x, byteLen),
    y: toBase64(y, byteLen),
    ext: true
  }
}

function unmarshalPrivateKey (curve, key) {
  const result = unmarshalPublicKey(curve, key.public)
  result.d = toBase64(new BN(key.private))
  return result
}
