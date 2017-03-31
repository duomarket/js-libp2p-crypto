'use strict'

const nodeify = require('nodeify')
const Buffer = require('safe-buffer').Buffer

const crypto = require('./webcrypto')()
const nCrypto = self.nCrypto
// const nCrypto = require('native-crypto')
const lengths = require('./hmac-lengths')

const hashTypes = {
  SHA1: 'SHA-1',
  SHA256: 'SHA-256',
  SHA512: 'SHA-512'
}

exports.create = function (hashType, secret, callback) {
  const hash = hashTypes[hashType]
  if (nCrypto) {
    callback(null, {
      digest (data, cb) {
        const hmac = new nCrypto.Hmac(hash.toLowerCase(), secret);
        nodeify(hmac.update(data).digest(), cb)
      },
      length: lengths[hashType]
    })
  } else {
    nodeify(crypto.subtle.importKey(
      'raw',
      secret,
      {
        name: 'HMAC',
        hash: {name: hash}
      },
      false,
      ['sign']
    ).then((key) => {
      return {
        digest (data, cb) {
          nodeify(crypto.subtle.sign(
            {name: 'HMAC'},
            key,
            data
          ).then((raw) => Buffer.from(raw)), cb)
        },
        length: lengths[hashType]
      }
    }), callback)
  }

}
