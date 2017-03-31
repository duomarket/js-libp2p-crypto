'use strict'

module.exports = function getWebCrypto () {
  if (!self.nCrypto) {
    console.log('nCrypto not found, will fall back on webcrypto');
  }
  try {
    const WebCrypto = require('node-webcrypto-ossl')
    const webCrypto = new WebCrypto()
    return webCrypto
  } catch (err) {
    // fallback to other things
  }
  return false
}
