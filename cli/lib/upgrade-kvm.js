"use strict";

const pem = require("pem");
const util = require("util");
const debug = require("debug")("upgradekvm");
const request = require("request");
const async = require('async');

const writeConsoleLog = require('microgateway-core').Logging.writeConsoleLog;

const CONSOLE_LOG_TAG_COMP = 'microgateway upgrade kvm';

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


function updateKvmEntries(options, entries, publicKey) {

    var updatekvmuri = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries",
    options.baseuri, options.org, options.env, options.kvm);
   
    async.parallel([
        
        function(cb) {
            let payload =  {
                "name": "private_key_kid",
                "value": options.kid
            }
            let uri = entries.findIndex( item => item.name === payload.name) !== -1 ? updatekvmuri + '/'+  payload.name : updatekvmuri;
            request({
                uri: uri,
                auth: generateCredentialsObject(options),
                method: "POST",
                json: payload
            }, function(err, res , body ) {
                if (err) {
                    if ( cb ) { cb(err) } else process.exit(1);
                    return;
                } if (res.statusCode !== 200 && res.statusCode !== 201) {
                    cb(new Error('Error updating KVM private_key_kid: '+ res.statusCode ))
                } else {
                    cb(null, body)
                }
            });
            
        },
        function(cb) {
            let payload = {
                "name": "public_key1",
                "value": publicKey.publicKey
            }
            let uri = entries.findIndex( item => item.name === payload.name) !== -1 ? updatekvmuri + '/'+  payload.name : updatekvmuri;
            request({
                uri: uri,
                auth: generateCredentialsObject(options),
                method: "POST",
                json: payload
            }, function(err, res , body ) {
                if (err) {
                    if ( cb ) { cb(err) } else process.exit(1);
                    return;
                } if (res.statusCode !== 200  && res.statusCode !== 201) {
                    cb(new Error('Error updating KVM public_key1: '+ res.statusCode ))
                } else {
                    cb(null, body)
                }
            });
        },
        function(cb) {
            let payload = {
                "name": "public_key1_kid",
                "value": options.kid
            }
            let uri = entries.findIndex( item => item.name === payload.name) !== -1 ? updatekvmuri + '/'+  payload.name : updatekvmuri;
            request({
                uri: uri,
                auth: generateCredentialsObject(options),
                method: "POST",
                json: payload
            }, function(err, res , body ) {
                if (err) {
                    if ( cb ) { cb(err) } else process.exit(1);
                    return;
                } if (res.statusCode !== 200  && res.statusCode !== 201) {
                    cb(new Error('Error updating KVM public_key1_kid: '+ res.statusCode ))
                } else {
                    cb(null, body)
                }
            });
        }
    ], function(err, results) {
        debug('error %s, private_key_kid %j, public_key1 %j, public_key1_kid %j', err,
            results[0], results[1], results[2]);

        if ( err ) {
            writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"error upgrading KVM: "+ err);
            process.exit(1);
        }
        else {
            writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"KVM update complete");
            process.exit(0);
        }
       
    });
}

function getKeys(options, cb){
    var URI = util.format("https://%s-%s.apigee.net/edgemicro-auth/keys", options.org, options.env);
    request({
        uri: URI,
        method: "GET"
    },function (err, res, body) {
        if (err){
            cb(err);
        } else {
            const keys = JSON.parse(res.body);
            cb(null, keys);
        } 
    });
}

function readKvmEntries(options, publicKey) {

    var getkvmuri = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s",
    options.baseuri, options.org, options.env, options.kvm);


    writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Reading kvm entries from %s ", getkvmuri);
    request({
        uri: getkvmuri,
        auth: generateCredentialsObject(options),
        method: "GET"
    }, function(err, res, body) {
        if (err) {
            writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP},err);
        } else {
            if ( res.statusCode === 200 ) {
                try {
                    body = JSON.parse(body);
                    if (  body && Array.isArray(body.entry) ) {
                        updateKvmEntries(options, body.entry, publicKey);
                    } else {
                        writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP}, 'Cannot continue with unexpected data', body);
                        process.exit(1);
                    }
                } catch (err) {
                    writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP}, 'Error in parsing data: %s, err: %s', body, err.message);
                    process.exit(1);
                }
               
            } else if ( res.statusCode === 404 ) {
                writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP}, 'KVM does not exist, Please run configure command');
                process.exit(1);
            } else {
                writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP}, 'Failed to read KVM values, statusCode: %d', res.statusCode);
                process.exit(1);
            }
        }
       }
    );

}


const UpgradeKVM = function () {

}

module.exports = function () {
  return new UpgradeKVM();
}

UpgradeKVM.prototype.upgradekvm = function upgradekvm(options, cb) {

    options.baseuri = options.mgmtUrl || "https://api.enterprise.apigee.com";
    options.kvm = 'microgateway';
    options.virtualhost = options.virtualhost || 'secure';    
    getKeys(options, function(err, keys) {
		if (err) {
            writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Error in upgrade kvm: "+ err);
            process.exit(1);
        } else {
            if (keys && keys.private_key_kid !== 'null'){
                options.kid = keys.private_key_kid
            } else{
                options.kid = '1';
            }
		}
    });

    var publicKeyURI = util.format('https://%s-%s.apigee.net/edgemicro-auth/publicKey', options.org, options.env);

    writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Checking for certificate...");
    request({
        uri: publicKeyURI,
        auth: generateCredentialsObject(options),
        method: "GET"
    }, function(err, res, body) {
        if (err) {
            writeConsoleLog('error',{component: CONSOLE_LOG_TAG_COMP},err);
        } else {
            writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},"Certificate found!");
            pem.getPublicKey(body, function(err, publicKey) {
                writeConsoleLog('log',{component: CONSOLE_LOG_TAG_COMP},publicKey.publicKey);

                readKvmEntries(options, publicKey);

            });
        }
       }
    );

}

