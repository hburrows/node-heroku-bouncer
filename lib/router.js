'use strict';

/**
 * @class Router
 */

var OAuth     = require('oauth').OAuth2;
var encryptor = require('simple-encryptor');
var express   = require('express');
var heroku    = require('heroku-client');
var fernet    = require('fernet');

/**
 * Create a router with the necessary routes for Heroku OAuth authentication.
 *
 * @method main
 * @param {Object} options options for configuring the router. See
 *   {{#crossLink "Main/main"}}Main#main{{/crossLink}} for configuration
 *   details.
 * @return {Express.Router} an Express.js router
 */
module.exports = function(options) {
  var cipher = encryptor(options.encryptionSecret);
  var oauth  = getOAuth();
  var router = new express.Router();

  router.get('/auth/heroku', function(req, res) {
    var param = req.query.redirectPath;
    var path  = param || req.headers.referer;

    if (!req.session.redirectPath) {
      req.session.redirectPath = path;
    }

    var params = { response_type: 'code', scope: options.oAuthScope, state: 'test_state' };

    // presense of HEROKU_PARENT_APP_NAME & HEROKU_APP_NAME indicates we're a review app
    // so pass fernet encrypted redirect in state so parent app can redirect /auth/heroku/callback
    // back to review app
    if (process.env.HEROKU_PARENT_APP_NAME && process.env.HEROKU_APP_NAME) {
      console.log('**** running as review app; including encrypted redirect in state');
      var secret = new fernet.Secret(process.env.FERNET_REVIEW_APP_SECRET);
      var token = new fernet.Token({secret: secret, ttl: 300});   // allow for 5 minutes to authenticate & redirect
      params.state = token.encode('https://' + process.env.HEROKU_APP_NAME + '.herokuapp.com/auth/heroku/callback');
    }

    res.redirect(oauth.getAuthorizeUrl(params));
  });

  router.get('/auth/heroku/callback', function(req, res) {
    oauth.getOAuthAccessToken(req.query.code, null, function(err, accessToken, refreshToken, results) {
      if (err) { console.log(err.toString()); console.dir(err); throw err; }

      var hk = heroku.createClient({
        token: accessToken,
        host : options.herokuAPIHost
      });

      hk.account().info(function(err, account) {
        if (err) throw err;

        var userSession = {
          accessToken : accessToken,
          refreshToken: refreshToken,
          createdAt   : (new Date()).toISOString(),
          expiresIn   : results.expires_in,

          user: {
            name : account.name,
            email: account.email,
            id   : account.id
          }
        };

        // function that handles the physical redirect.
        function handleRedirect() {

          var redirectPath;

          if (options.sessionSyncNonce) {
            var nonceName = options.sessionSyncNonce;
            req.session.herokuBouncerSessionNonce = req.cookies[nonceName];
          }

          req.session.userSession = cipher.encrypt(userSession);

          if (!req.session.redirectPath || req.path === '/auth/heroku') {
            redirectPath = '/';
          } else {
            redirectPath = req.session.redirectPath;
          }

          delete req.session.redirectPath;
          res.redirect(redirectPath);
        }

        // optional callback to signal a new session was created
        if (options.newSessionCallback) {
          options.newSessionCallback(accessToken, refreshToken)
          .then(function () {
            handleRedirect();
          })
          .catch(function(err) {
            // TODO cleanup error handling
            console.log('Error from newSessionCallback' + err.toString());
            res.status(502).send('Unexpected response.  Status: ' + err.__statusCode +
                                    ', Response: ' + (err.__response ? err.__response : '-') +
                                    ', Exception msg: ' + err.toString() +
                                    ', Headers: ' + JSON.stringify(err.__headers));
          });
        }
        else {
          handleRedirect();
        }

      });
    });
  });

  router.get('/auth/heroku/logout', function(req, res) {
    req.session.reset();
    res.redirect(options.oAuthServerURL + '/logout');
  });

  function getOAuth() {
    return new OAuth(
      options.oAuthClientID,
      options.oAuthClientSecret,
      options.oAuthServerURL,
      '/oauth/authorize',
      '/oauth/token'
    );
  }

  return router;
};
