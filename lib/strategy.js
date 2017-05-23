/**
 * Module dependencies.
 */
const passport = require('passport');
const util = require('util');
const LdapValidator = require('./LdapValidator');

/**
 * `Strategy` constructor.
 *
 * Applications might supply credentials for an Active Directory and the strategy will fetch
 * the profile from there.
 *
 * Options:
 *   - `ldap` connection options
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new WindowsAuthentication({
 *      ldap: {
 *        url:         'ldap://mydomain.com/',
 *        base:        'DC=wellscordobabank,DC=com',
 *        bindDN:          'AppUser',
 *        bindCredentials: 'APassword'
 *      }
 *        }, function(profile, done) {
 *         User.findOrCreate({ waId: profile.id }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy (options, verify) {
  if (typeof verify !== 'function') {
    throw new Error('windows authentication strategy requires a verify function');
  } else if (!options) {
      throw new Error('invalid options');
  } else if(!options.ldap || !options.ldap.url) {
    throw new Error('ldap url should be provided in order to validate user and passwords');
  }

  passport.Strategy.call(this);

  this.name = 'WindowsAuthentication';
  this._verify = verify;

  this._passReqToCallback = options.passReqToCallback;

  this._usernameField = options.usernameField || 'username';
  this._passwordField = options.passwordField || 'password';

  this._ldapValidator = new LdapValidator(options.ldap);
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * maps the user profile.
 */
Strategy.prototype.mapProfile = function (i) {
  if (!i) return i;

  let result = {
    id:          i.objectGUID || i.uid,
    displayName: i.displayName,
    name: {
      familyName: i.sn || i.surName,
      givenName: i.gn || i.givenName
    },
    emails: (i.mail ? [{value: i.mail }] : undefined),
    _json: i
  };

  return result;
};

/**
 * Authenticate request based on the contents of the x-iisnode-logon_user header
 *
 * @param {Object} req
 * @param {Object} [options={}]   used in passport logic
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options={}) {
  let self = this;
  let userName, password;

  userName = req.body[this._usernameField] || req.query[this._usernameField];
  password = req.body[this._passwordField] || req.query[this._passwordField];

  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }

  this._ldapValidator.validate(userName, password, function(err, userProfile){
    if (err) return self.error(err);
    userProfile = userProfile ? self.mapProfile(userProfile) : null;
    if (self._passReqToCallback) {
      self._verify(req, userProfile, verified);
    } else {
      self._verify(userProfile, verified);
    }
  });
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;