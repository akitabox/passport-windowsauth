const async = require('async');
const ldap = require('ldapjs');
const decodeSearchEntry = require('./decodeSearchEntry');

const DEFAULT_SEARCH_QUERY = '(&(objectclass=user)(|(sAMAccountName={0})(UserPrincipalName={0})))';

/**
 * Contains methods to lookup and validate a user vial LDAP. Creates a fresh LDAP connection
 * with each validation attempt.
 *
 * @param {Object} options                      - ldapjs client connection options
 *                                                Reference http://ldapjs.org/client.html
 * @param {String} options.url
 * @param {Number} [options.maxConnections=10]
 * @param {String} [options.bindDN]
 * @param {String} [options.bindCredentials]
 * @param {Object} [options.tlsOptions]
 * @param {Boolean} [options.reconnect=false]
 * @param {Number} [options.timeout]
 * @param {Number} [options.connectTimeout]
 * @param {Number} [options.idleTimeout]
 * @constructor
 */
let LdapValidator = function (options) {
  this._options = Object.assign({}, options);
  this._search_query = options.search_query || DEFAULT_SEARCH_QUERY;
};

/**
 * Returns a new ldapjs client
 *
 * @return {Object}
 * @private
 */
LdapValidator.prototype._createClient = function () {
  let opts = this._options;
  return ldap.createClient({
    url:             opts.url,
    maxConnections:  opts.maxConnections || 10,
    bindDN:          opts.bindDN,
    bindCredentials: opts.bindCredentials,
    tlsOptions:      opts.tlsOptions,
    reconnect:       opts.reconnect,
    timeout:         opts.timeout,
    connectTimeout:  opts.connectTimeout,
    idleTimeout:     opts.idleTimeout
  });
};

/**
 * Attempt to lookup the provided user and authenticate the user with the provided password via LDAP.
 * Operates within the passport paradigm.
 *
 * @param {String} username
 * @param {String} password
 * @param {Function} callback
 */
LdapValidator.prototype.validate = function (username, password, callback) {
  let self = this;
  let notSent = true;
  let userProfile = null;
  let isAuthenticated = false;

  if (typeof username !== 'string' || !username.length) {
    return _callback();
  } else if (typeof password !== 'string' || !password.length) {
    return _callback();
  }

  let client = this._createClient();
  client.on('error', function (err){
    // Suppress ECONNRESET error if ldapjs's Client will automatically reconnect
    if (err.errno === 'ECONNRESET' && client.reconnect) return;
    console.log('LDAP connection error: ', err);
    return _callback(err);
  });

  async.series([bind, search, unbind, validate], _callback);

  /**
   * Bind the ldapjs client to the provided service account in the provided AD
   * @param {Function} cb
   */
  function bind (cb) {
    // bind to the service account so we can search for other accounts
    client.bind(self._options.bindDN, self._options.bindCredentials, function (err) {
      if (err) console.log(`Error binding to LDAP with dn:  + ${err.dn}`, err);
      return cb(err);
    });
  }

  /**
   * Try to search for the user's AD profile
   * @param {Function} cb
   */
  function search (cb) {
    let entries = [];
    let notCbSent = true;
    let opts = {
      scope: 'sub',
      filter: self._search_query.replace(/\{0\}/ig, username)
    };

    client.search(self._options.base, opts, function (err, res){
      if (err) {
        console.log(`LDAP search error:`, err);
        return _cb(err);
      }
      res.on('searchEntry', function (entry) {
        entries.push(entry);
      });
      res.on('error', function (e) {
        console.log(`LDAP search response error:`, err);
        return _cb(e);
      });
      res.on('end', function () {
        if(entries.length) userProfile = decodeSearchEntry(entries[0]);
        // not finding any matches is NOT an error by passport standards
        return _cb();
      });
    });

    function _cb (err) {
      if (notCbSent) {
        notCbSent = false;
        return cb(err);
      }
    }
  }

  /**
   * Unbind from the service account so we can try to bind to the user's account
   * @param {Function} cb
   */
  function unbind (cb) {
    client.unbind(function (err) {
      if (err) console.log('LDAP unbinding error', err);
      return cb(err);
    });
  }

  /**
   * Validate the user's provided password now that we know the user's dn
   * @param {Function} cb
   */
  function validate (cb) {
    if (!userProfile || !userProfile.dn) {
      // skip this if we did not find a matching user
      return cb();
    }

    client.bind(userProfile.dn, password, function(err) {
      if (err) {
        // did not find a matching user (password did not match)
        // do not pass this err bc of passport standards
        return cb();
      }
      // successful authentication with provided credentials
      isAuthenticated = true;
      return cb();
    });
  }

  /**
   * Only return callback once
   * (multiple events may fire triggering multiple invocations)
   *
   * @param err
   * @private
   */
  function _callback (err) {
    if (client && client.destroy) client.destroy();

    if (notSent) {
      notSent = false;
      // only return the user profile if authentication succeeded
      return callback(err, isAuthenticated ? userProfile : null);
    }
  }
};

module.exports = LdapValidator;
