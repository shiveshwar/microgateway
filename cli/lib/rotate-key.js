"use strict";

const pem = require("pem");
const util = require("util");
const debug = require("debug")("jwkrotatekey");
//const commander = require('commander');
const request = require("request");
const async = require('async');
const writeConsoleLog = require('microgateway-core').Logging.writeConsoleLog;

const CONSOLE_LOG_TAG_COMP = 'microgateway rotate key';

function createCert(cb) {

    const options = {
        selfSigned: true,
        days: 1
    };

    pem.createCertificate(options, cb);
}

function generateCredentialsObject(options) {
    if (options.token) {
        return {
            "bearer": options.token
        };
    } else {
        return {
            user: options.username,
            pass: options.password
        };
    }
}

function isCPS(property) {
    var cpsenabled = false;
	debug(property);
    for (var p in property) {
        if (property.hasOwnProperty(p)) {
            if ( (property[p].name ===  "features.isCpsEnabled") && (typeof property[p].value !== "undefined") ) {
				var b = property[p].value
				if ( ((typeof b === 'string') && (b.toLocaleLowerCase() === 'true')) || ((typeof b === 'boolean') && b) ) {
					cpsenabled = true;
				}
            }
        }
    }
	return cpsenabled;	
}

function updateNonCPSKVM(options, serviceKey, newCertificate, newPublicKey, oldPublicKey) {
	
	var updatekvmuri = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s",
    		options.baseuri, options.org, options.env, options.kvm);
		
    var payload = {
        "name": options.kvm,
        "encrypted": "true",
        "entry": [{
                "name": "private_key",
                "value": serviceKey
            },
            {
                "name": "private_key_kid",
                "value": options.kid
            },
            {
                "name": "public_key",
                "value": newCertificate
            },
            {
                "name": "public_key1",
                "value": newPublicKey
            },
            {
                "name": "public_key1_kid",
                "value": options.kid
            },
            {
                "name": "public_key2",
                "value": oldPublicKey
            },
            {
                "name": "public_key2_kid",
                "value": options.oldkid
            }
        ]
    };
	debug(payload);	
    request({
       uri: updatekvmuri,
       auth: generateCredentialsObject(options),
       method: "POST",
       json: payload
    }, function(err, res /*, body */) {
       if (err || res.statusCode > 299) {
           writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP},err);
       } else {
           writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Key Rotation successfully completed!");
       }
    });	
}

function checkKVMEntry(options, key, cb) {
	var entryuri = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries/%s",
	options.baseuri, options.org, options.env, options.kvm, key);

    request({
        uri: entryuri,
        auth: generateCredentialsObject(options),
        method: "GET",
    }, function(err, res /*, body */) {
        if (err){
			cb(err);
		} else{
			if (res.body && res.body.name === 'public_key2_kid'){
				cb(null, true);
			} else{
				cb(null, false);
			}
		}
    });						
}

function insertKVMEntry(options, key, value, cb) {
	var entryuri = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries",
	options.baseuri, options.org, options.env, options.kvm);
	var entry = {
		"name": key,
		"value": value
	};
    debug(entry);
    request({
        uri: entryuri,
        auth: generateCredentialsObject(options),
        method: "POST",
		json: entry
    }, function(err, res /*, body */) {
        if (err || res.statusCode > 299) cb(err);
		else cb(null, true);
	});	

}

function updateKVMEntry(options, key, value, cb) {
	var entryuri = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries/%s",
	options.baseuri, options.org, options.env, options.kvm, key);
	var entry = {
		"name": key,
		"value": value
	};
    debug(entry);
    request({
        uri: entryuri,
        auth: generateCredentialsObject(options),
        method: "POST",
		json: entry
    }, function(err, res /*, body */) {
        if (err || res.statusCode > 299) cb(err);
		else cb(null, true);
	});
}

function updateOrInsertEntry (options, key, value, cb) {
	checkKVMEntry(options, key, function(err, isKvmEntry) {
		if (err) {
            writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Error in rotate key while checking kvm entry: "+ err);
            process.exit(1);
        } else if (isKvmEntry){
			debug("entry exists, updating..");
			updateKVMEntry(options, key, value, function(err /*, result */){
				if (err) cb(err);
				else cb(null, true);
			});
		} else{
			debug("entry does not exist. inserting entry...")
			insertKVMEntry(options, key, value, function(err /*, result */){
				if (err) cb(err);
				else cb(null, true);
			});	
		}
	});
}

function updateCPSKVM(options, serviceKey, newCertificate, newPublicKey, oldPublicKey) {
	var updatecpskvmuri = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries/",
					options.baseuri, options.org, options.env,options.kvm);	

	async.parallel([
		function (cb) {
			var entry = {
				name: "private_key",
				value: serviceKey
			};
			debug(entry);
            request({
                uri: updatecpskvmuri+"private_key",
                auth: generateCredentialsObject(options),
                method: "POST",
                json: entry
            }, function(err, res, body) {
                cb(err, body);
            });						
		},
		function (cb) {
			var entry = {
				name: "private_key_kid",
				value: options.kid
			};
			debug(entry);
            request({
                uri: updatecpskvmuri+"private_key_kid",
                auth: generateCredentialsObject(options),
                method: "POST",
                json: entry
            }, function(err, res, body) {
                cb(err, body);
            });						
		},
		function (cb) {
			var entry = {
				name: "public_key",
				value: newCertificate
			};
			debug(entry);
            request({
                uri: updatecpskvmuri+"public_key",
                auth: generateCredentialsObject(options),
                method: "POST",
                json: entry
            }, function(err, res, body) {
                cb(err, body);
            });						
		},
		function (cb) {
			var entry = {
				name: "public_key1",
				value: newPublicKey
			};
			debug(entry);
            request({
                uri: updatecpskvmuri+"public_key1",
                auth: generateCredentialsObject(options),
                method: "POST",
                json: entry
            }, function(err, res, body) {
                cb(err, body);
            });						
		},
		function (cb) {
			var entry = {
				name: "public_key1_kid",
				value: options.kid
			};
			debug(entry);
            request({
                uri: updatecpskvmuri+"public_key1_kid",
                auth: generateCredentialsObject(options),
                method: "POST",
                json: entry
            }, function(err, res, body) {
                cb(err, body);
            });						
		},
		function (cb) {
			updateOrInsertEntry(options, "public_key2", oldPublicKey, function(err, result) {
				cb(err, result); 
			});				
		},
		function (cb) {
			updateOrInsertEntry(options, "public_key2_kid", options.oldkid, function(err, result) {
				cb(err, result); 
			});				
		}												
	], function (err /*, results */) {
		if (err) {
			writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP},err);
			process.exit(1);
		} else {
			writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Key Rotation successfully completed!");
		}
    });
}

function validateKeys(options, cb){
    var URI = util.format("https://%s-%s.apigee.net/edgemicro-auth/keys", options.org, options.env);
    request({
        uri: URI,
        method: "GET"
    },function (err, res) {
        if (err){
            cb(err);
        } else {
            const keys = JSON.parse(res.body);
            cb(null, keys);
        } 
    });
}

const RotateKey = function () {

}

module.exports = function () {
  return new RotateKey();
}

RotateKey.prototype.rotatekey = function rotatekey(options /*, cb */) {

    options.baseuri = options.mgmtUrl || "https://api.enterprise.apigee.com";
    options.kvm = "microgateway";
	options.kid =  options.kid;

	validateKeys(options, function(err, keys) {
		if (err) {
            writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Error in rotate key: "+ err);
            process.exit(1);
        } else {
			// check kid is exists or not.
			if (options.kid === keys.private_key_kid){
				writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP}, "kid : " + keys.private_key_kid + " alredy exist try with other key");
				process.exit(1);
			} else if (options["prevKid"] || keys.public_key1_kid !=='null'){
				options.oldkid = options["prevKid"] || keys.public_key1_kid;
			} else{
				writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Error in rotate key to get old key kid");
				process.exit(1);
			}
		}
	});

    async.series([
    	function(cb) {
		    var privateKeyURI = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries/private_key",
		        options.baseuri, options.org, options.env, options.kvm);
		    writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Checking if private key exists in the KVM...");
		    request({
		        uri: privateKeyURI,
		        auth: generateCredentialsObject(options),
		        method: "GET"
		    }, function (err, resp, body) {
		    	if (err) cb(err);
				else cb(null,body);
		    }); 		
    	},
		function(cb) {
			writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Checking for certificate...");
            var publicKeyURI = util.format("https://%s-%s.apigee.net/edgemicro-auth/publicKey",
                options.org, options.env);			
            request({
                uri: publicKeyURI,
                auth: generateCredentialsObject(options),
                method: "GET"
            }, function (err, resp, body) {
				if (err) cb(err);
				else cb (null, body);	
            });
		}
    ], function(err, results){
    	if (err) {
			writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP},err);
			process.exit(1);
    	} else {
    		var oldCertificate = results[1];
			writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Found Certificate");
			//debug("Old Certificate: \n" + oldCertificate);
			async.series([
				function(cb) {
					pem.getPublicKey(oldCertificate, function(e, oldPublicKey) {
						if (e) cb(e);
						else cb(null, oldPublicKey);
					});
				}, 
				function(cb) {
					writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Generating New key/cert pair...");
					createCert(function(e, newkeys) {
						if (e) cb(e);
						else cb(null, newkeys);
					});								
				}
			], function(e, res){
				if (err) {
					writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP},e);
					process.exit(1);
				} else {
					writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Extract new public key");
					var newCertificate = res[1].certificate;
					pem.getPublicKey(newCertificate, function(ee, newkey) {
						if (ee) {
							writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP},ee);
							process.exit(1);
						} else {
							debug("Checking for CPS...");
							var cpsuri = util.format("%s/v1/o/%s", options.baseuri, options.org);
							request({
                                uri: cpsuri,
                                auth: generateCredentialsObject(options),
                                method: "GET"
                            }, function(eee, rs, body) {
								var payload = JSON.parse(body);
								var property = payload.properties.property;
								if (isCPS(property)) {
									debug("CPS is enabled");
									updateCPSKVM(options, res[1].serviceKey, newCertificate, newkey.publicKey, res[0].publicKey);
								} else {
									debug("CPS is not enabled");
									updateNonCPSKVM(options, res[1].serviceKey, newCertificate, newkey.publicKey, res[0].publicKey);
								}
							});							
						}
					});
				}
			});			
    	}
    });
}
