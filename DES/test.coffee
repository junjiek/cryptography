Crypto = (require './cryptojs').Crypto
key = "12345678"
us = ''
for i in [0...1000000] by 1
    us += 'a'

mode = new Crypto.mode.CBC Crypto.pad.pkcs7
ub = Crypto.charenc.UTF8.stringToBytes us
eb = Crypto.DES.encrypt ub, key, {asBytes: true, mode: mode}
fs= require('fs')
fs.writeFile('./res/DES_CBC.txt', "#{ehs= Crypto.util.bytesToHex eb}");

mode = new Crypto.mode.OFB Crypto.pad.pkcs7
ub = Crypto.charenc.UTF8.stringToBytes us
eb = Crypto.DES.encrypt ub, key, {asBytes: true, mode: mode}
fs= require('fs')
fs.writeFile('./res/DES_OFB.txt', "#{ehs= Crypto.util.bytesToHex eb}");

mode = new Crypto.mode.CTR Crypto.pad.pkcs7
ub = Crypto.charenc.UTF8.stringToBytes us
eb = Crypto.DES.encrypt ub, key, {asBytes: true, mode: mode}
fs= require('fs')
fs.writeFile('./res/DES_CTR.txt', "#{ehs= Crypto.util.bytesToHex eb}");
