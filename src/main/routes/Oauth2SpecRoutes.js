const escape = require('escape-html');
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt');
const Oauth2SpecService = require('../services/logic/Oauth2SpecService.js');

function Oauth2SpecRoutes(oauth2SpecService, expressInstance) {

  this.oauth2SpecService = oauth2SpecService;
  this.expressInstance = expressInstance;

  this.configure = () => {
    //TODO: detect if body-parser urlencoded/json are configured
    return new Promise((resolve, reject) => {
      this.expressInstance.post("/oauth2/token", tokenRoute);
      this.expressInstance.post("/oauth2/token/introspect", introspectTokenRoute);
      console.log(`registered route: Oauth2SpecRoutes.tokenRoute endpoint:/oauth2/token method:post`);
      resolve()
    })
  }

  tokenRoute = async (req, res) => {

    if (!req.is('application/x-www-form-urlencoded')) {
      res.status(400);
      return res.json({
        code: 400001,
        message: "unsupported content type"
      });
    }

    var tokenResponse;
    try {
      tokenResponse = await this.oauth2SpecService.generateToken(req);      
    } catch (e) {
      console.log(e);
      res.status(500);
      return res.json({
        code: 500000,
        message: "internal error"
      });
    }

    if(tokenResponse && typeof tokenResponse.code === 'number'){
      res.status(Math.round(tokenResponse.code/1000));
    }else{
      res.status(500);
    }

    return res.json(tokenResponse);
  }

  //https://www.rfc-editor.org/rfc/rfc7662
  introspectTokenRoute = async (req, res) => {

    if (!req.is('application/json') && !req.is('application/x-www-form-urlencoded')) {
      res.status(400);
      return res.json({
        code: 400001,
        message: "unsupported content type"
      });
    }

    try {
      var tokenInfo = await this.oauth2SpecService.introspectToken(req.body.token);
      res.status(200);
      tokenInfo.active = true;
      return res.json({
        code: 200000,
        message: "success",
        content: tokenInfo
      });
    } catch (e) {
      console.log(e);
      res.status(500);
      return res.json({
        code: 500410,
        message: "token is not active",
        content: {
          active: false
        }
      });
    }
  }
}

module.exports = Oauth2SpecRoutes;
