var tools = require('../tools/tools.js');
var jwt = require('../tools/jwt.js');
var express = require('express');
var router = express.Router();

var redis = require('redis');
var client = redis.createClient();

let schedule = require('node-schedule');
let request = require('request');

client.on('connect', () => {
  console.log('Redis_connected in callback.js');
});

/** /callback **/
router.get('/', function(req, res) {
  // Verify anti-forgery
  if (!tools.verifyAntiForgery(req.session, req.query.state)) {
    return res.send('Error - invalid anti-forgery CSRF response!');
  }

  // Exchange auth code for access token
  tools.intuitAuth.code.getToken(req.originalUrl).then(
    function(token) {
      // Store token - this would be where tokens would need to be
      // persisted (in a SQL DB, for example).
      tools.saveToken(req.session, token);

      //refresh token hourly
      let j = schedule.scheduleJob('*/59 * * * *', function() {
        console.log('Schedule refresh token are called');
        let accessTokenFake, refreshToken, tokenType, data;
        client.get('accessToken', (err, reply) => {
          accessTokenFake = reply;
          client.get('refreshToken', (err, reply) => {
            refreshToken = reply;
            client.get('tokenType', (err, reply) => {
              tokenType = reply;
              client.get('data', (err, reply) => {
                data = reply;

                let fakeToken = {
                  accessToken: accessTokenFake,
                  refreshToken: refreshToken,
                  tokenType: tokenType,
                  data: data
                };
                tools.refreshTokens(fakeToken).then(
                  function(newToken) {
                    // We have new tokens!
                    console.log('Schedule refresh token is' + newToken);
                  },
                  function(err) {
                    // Did we try to call refresh on an old token?
                    console.log(err);
                    res.json(err);
                  }
                );
              });
            });
          });
        });
      });
      //dont touch
      req.session.realmId = req.query.realmId;
      client.set('realmId', '123145629669197', function(err, reply) {
        console.log('callback.js: realmId saved to redis: ' + reply);
      });
      var errorFn = function(e) {
        console.log('Invalid JWT token!');
        console.log(e);
        res.redirect('/');
      };

      if (token.data.id_token) {
        try {
          // We should decode and validate the ID token
          jwt.validate(
            token.data.id_token,
            function() {
              // Callback function - redirect to /connected
              res.redirect('connected');
            },
            errorFn
          );
        } catch (e) {
          errorFn(e);
        }
      } else {
        // Redirect to /connected
        res.redirect('connected');
      }
    },
    function(err) {
      console.log(err);
      res.send(err);
    }
  );
});

module.exports = router;
