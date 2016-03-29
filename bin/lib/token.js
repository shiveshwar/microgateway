
'use strict';

const request = require('request');
const util = require('util');
const fs = require('fs');
const path = require('path');
const edgeconfig = require('microgateway-config');
const jwt = require('jsonwebtoken');
const assert = require('assert')

const configLocations = require('../../config/locations');
 

const Token = function() {
};

module.exports = function(){
  return new Token();
}
Token.prototype.decodeToken = function(options) {
  if (!options.file) { return optionError.bind(options)('file is required'); }

  const jtw = require('../api/helpers/jwt');
  const token = fs.readFileSync(path.resolve(options.file), 'utf8').trim();
  jtw.decode(token, function(err, result) {
    if (err) { return printError(err); }
    console.log(result);
  });
}

Token.prototype.verifyToken = function(options) {

  if (!options.file) { return optionError.bind(options)('file is required'); }
  if (!options.org) { return optionError.bind(options)('org is required'); }
  if (!options.env) { return optionError.bind(options)('env is required'); }
  const targetPath = configLocations.getSourcePath(options.org,options.env);

  const key = options.key;
  const secret = options.secret;
  const keys = { key: key, secret: secret };

  const token = fs.readFileSync(path.resolve(options.file), 'utf8').trim();

  const config = edgeconfig.load({ source: targetPath, keys: keys });

  const authUri = config.edge_config['authUri'];
  this.isPublicCloud = config.edge_config['managementUri'] === 'https://api.enterprise.apigee.com';

  getPublicKey(options.org, options.env, authUri, this.isPublicCloud, function(err, certificate) {
    if (err) { return printError(err); }

    const opts = {
      algorithms: ['RS256'],
      ignoreExpiration: false
    };

    jwt.verify(token, certificate, opts, function(err, result) {
      if (err) { return printError(err); }
      console.log(result);
    });
  });


}

Token.prototype.getToken = function(options, cb) {

  if (!options.org) { return optionError.bind(options)('org is required'); }
  if (!options.env) { return optionError.bind(options)('env is required'); }
  if (!options.id) { return optionError.bind(options)('client id is required'); }
  if (!options.secret) { return optionError.bind(options)('client secret is required'); }
  const targetPath = configLocations.getSourcePath(options.org,options.env);

  const key = options.key;
  const secret = options.secret;
  const keys = { key: key, secret: secret };
  const config = edgeconfig.load({ source: targetPath, keys: keys });
  const authUri = config.edge_config['authUri'];
  this.isPublicCloud = config.edge_config['managementUri'] === 'https://api.enterprise.apigee.com';
  const uri = this.isPublicCloud ? util.format(authUri + '/token', options.org, options.env) : authUri + '/token';
  const body = {
    client_id: options.id,
    client_secret: options.secret,
    grant_type: 'client_credentials'
  };
  request({
    uri: uri,
    method: 'POST',
    json: body
  }, function(err, res) {
    if (err) {
      cb && cb(err)
      return printError(err)
    }
    console.log(res.body)
    cb && cb(null, res.body)
  });
}

function getPublicKey(organization, environment, authUri, isPublicCloud, cb) {

  const uri = isPublicCloud ? util.format(authUri + '/publicKey', organization, environment) : authUri + '/publicKey';
  request({
    uri: uri
  }, function(err, res) {
    if (err) { return cb(err); }
    cb(null, res.body);
  });
}

function printError(err) {
  if (err.response) {
    console.log(err.response.error);
  } else {
    console.log(err);
  }
}

function optionError(message) {
  console.error(message);
  this.help();
}
