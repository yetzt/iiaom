#!/usr/bin/env node
/* iiaom command line interface */

/* node modules */
var fs = require("fs");
var path = require("path");

/* npm modules */
var commander = require("commander");
var read = require("read");

/* local modules */
var iiaoum = require(path.resolve(__dirname, "..", "lib", "iiaom.js"));

/* package.json */
var pkg = require(path.resolve(__dirname, "..", "package.json"));

/* command line options */
commander
	.version(pkg.version)
	.usage('[options] command <file>')
	.option('create <file>', 'create a new id')
	.option('verify <idfile.iiaom>', 'verify an id')
	.option('-s, --safe', 'destroy input file after id creation')
	.option('-p, --publish', 'publish generated identity')
	.option('-k, --pubkey', 'use different pgp pubkey')
	.parse(process.argv)

/* iiaom instance */
var ii = new iiaoum({
	pubkey: commander.pubkey
}, function(err, ii){
	if (err) {
		console.error("error:", err);
		process.exit(-1);
	}
	/* switch mode */
	if (commander.create) {
		if (!fs.existsSync(path.resolve(process.cwd(), commander.create))) {
			console.error("file not found:", commander.create);
			process.exit(-1);
		}
		read({
			prompt: "enter your password:",
			silent: true,
			replace: "*"
		}, function(err, password){
			if (password.length < 10) {
				console.error("this password ist way too short. protect your identity with 10 characters at least");
				process.exit(-1);
			}
			ii.generate(commander.create, password, function(err, filename, bytes){
				if (err) {
					console.error("error:", err);
					process.exit(-1);
				}
				console.log("generated identity:", filename);
				console.log("size:", bytes, "bytes");
				process.exit(0);
			});
		});
	} else if (commander.verify) {
		if (!fs.existsSync(path.resolve(process.cwd(), commander.create))) {
			console.error("file not found:", commander.create);
			process.exit(-1);
		}
		read({
			prompt: "enter your password:",
			silent: true,
			replace: "*"
		}, function(err, password){
			ii.verify(commander.create, password, function(err, success, identity){
				if (err) {
					console.error("error:", err);
					process.exit(-1);
				}
				if (!success) {
					console.error("this identity could not be verified");
					process.exit(0);
				} else {
					console.error("OK! this identity is yours.");
					process.exit(0);
				}
			});
		});
		
	} else {
		console.error("please specify a command");
		process.exit(-1);
	}
});

