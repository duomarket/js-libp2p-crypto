'use strict'

const Buffer = require('safe-buffer').Buffer

const crypto = require('./webcrypto')()

exports.getRandomValues = function (arr) {
  return Buffer.from(crypto.getRandomValues(arr))
}
