#!/usr/bin/env node

/* node modules */
var fs = require("fs");
var path = require("path");
var crypto = require("crypto");

/* npm modules */
var openpgp = require("openpgp");

/* root folder */
__root = path.dirname(module.parent.filename);

function iiaom(config, callback){
	
	if (!(this instanceof iiaom)) return new iiaom(config, callback);
	
	var self = this;
	
	var pubkey_file = path.resolve(__root, "etc", "pubkey.asc");
	if (config && config.hasOwnProperty("pubkey")) pubkey_file = path.resolve(process.cwd(), config.pubkey);

	fs.exists(pubkey_file, function(exists){
		if (!exists) throw new Error("pubkey file not found: "+pubkey_file);
		fs.readFile(pubkey_file, function(err, pubkey_data){
			if (err) throw err;
			self.pubkey = openpgp.key.readArmored(pubkey_data.toString()).keys;
			callback(self);
		});
	});
	
	return this;
	
};

iiaom.prototype.generate = function(file, password, callback){
	var self = this;
	var file = path.resolve(process.cwd(), file);
	fs.exists(file, function(exists){
		if (!exists) throw new Error("file not found: "+file);
		
		/* create aes256 key from password and salt */
		var _key = crypto.pbkdf2Sync(password, "replace me", 1000, 256);
		
		/* sha256 hash from original data */
		var _hash = crypto.createHash("sha256");;

		/* aes256 cipher to encrypt original data */
		var _cipher = crypto.createCipher('aes256', _key);

		/* array of data buffers for pgp encryption */
		var _data = [];
		
		/* read stream from original file */
		fs.createReadStream(file).on('data', function(d) { 
		
			/* update hash with data chunk */
			_hash.update(d);
			
			/* update cipher with data chunk */
			_cipher.update(d, 'binary', 'binary');

			/* push chunk buffer */
			_data.push(d);
			
		}).on('end', function() {
			
			/* finalize hash of original data */
			var _sha_hash = _hash.digest('hex');

			/* finalize encryption of original data */
			var _encrypted_aes_binary = _cipher.final('binary');

			/* finalize pgp encryption and put it in ascii armor */
			var _encrypted_pgp_binary = openpgp.message.fromBinary(Buffer.concat(_data)).encrypt(self.pubkey).packets.write()
			var _encrypted_pgp_ascii = openpgp.armor.encode(openpgp.enums.armor.message, _encrypted_pgp_binary);

			/* create hash of armored pgp */
			var _encrypted_pgp_hash = crypto.createHash("sha256").update(_encrypted_pgp_ascii).digest("hex");

			var _public_id = _sha_hash+_encrypted_pgp_hash;

			console.log("pubid", _public_id);

			// todo: write data to container
			
		});
	});
	return this;
};

iiaom.prototype.hash = function(data) {
	return crypto.createHash("sha256").update(data).digest("hex");
};

module.exports = iiaom;
