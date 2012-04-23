if (typeof define !== 'function') { var define = (require('amdefine'))(module); }

define([
  "compose",
  "./_errors",
  "promised-io/request",
  "promised-io/lib/adapters!lang",
  "promised-io/lib/adapters!http",
  "crypto", // FIXME: Abstract Node.js dependencies
  "querystring"
], function(Compose, errors, request, lang, http, crypto, querystring){
  "use strict";

  var RFC3986_MAP = { "!": "%21", "'": "%27", "(": "%28", ")": "%29", "*": "%2A" };
  var REPLACE_CHARS = /([!'()*])/g;
  function encodeRfc3986(str){
    return encodeURIComponent(str).replace(REPLACE_CHARS, function(c){ return RFC3986_MAP[c]; });
  }

  return Compose(function(options){
    options = options || {};

    this.id = options.id;
    if(options.callback){
      this.callback = options.callback;
    }
    if(options.version){
      this.version = options.version;
    }
    if(options.signatureMethod){
      this.signatureMethod = options.signatureMethod;
    }
    if(this.signatureMethod !== "PLAINTEXT" && this.signatureMethod !== "HMAC-SHA1"){
      throw new Error("Unsupported signature method: " + this.signatureMethod);
    }
    if(options.generateNonce){
      this._generateNonce = options.generateNonce;
    }

    if(options.tempCredentialsEndpoint){
      this._normalizedTempCredentialsEndpoint = http.normalizeOptions(options.tempCredentialsEndpoint);
    }
    if(options.tokenCredentialsEndpoint){
      this._normalizedTokenCredentialsEndpoint = http.normalizeOptions(options.tokenCredentialsEndpoint);
    }

    // We don't store the secrets on the instance itself, that way it can
    // be passed to other actors without leaking
    var secret = encodeRfc3986(options.secret);
    var signatureMethod = this.signatureMethod;
    this._createSignature = function(tokenSecret, baseString){
      if(baseString === undefined){
        baseString = tokenSecret;
        tokenSecret = "";
      }

      var key = secret + "&" + tokenSecret;
      if(signatureMethod == "PLAINTEXT"){
        return key;
      }else{
        return crypto.createHmac("SHA1", key).update(baseString).digest("base64");
      }
    };
  }, {
    id: null,
    callback: "oob",
    version: null,
    signatureMethod: "HMAC-SHA1",
    _normalizedTempCredentialsEndpoint: null,
    _normalizedTokenCredentialsEndpoint: null,

    _generateNonce: function(){
      return crypto.randomBytes(16).toString("hex");
    },

    _getTimestamp: function(){
      return Math.floor(Date.now() / 1000).toString();
    },

    _resolveEndpoint: function(endpoint, query){
      endpoint = http.normalizeOptions(endpoint);
      if(query){
        if(endpoint.query){
          endpoint.query += "&" + query;
        }else{
          endpoint.query = query;
        }
      }
      return endpoint;
    },

    _buildBaseUri: function(options){
      var baseUri = options.protocol + "//" + options.hostname;
      if(options.protocol === "http:" && options.port && (options.port + "") !== "80"){
        baseUri += ":" + options.port;
      }
      if(options.protocol === "https:" && options.port && (options.port + "") !== "443"){
        baseUri += ":" + options.port;
      }
      return baseUri + options.pathname;
    },

    _collectParams: function(options){
      var params = {
        oauth: {},
        pairs: []
      };

      if(options.query){
        var queryObj = querystring.parse(options.query);
        lang.forIn(queryObj, function(value, name){
          params.pairs.push([name, value]);
        });
      }
      // FIXME: Assumes options.form is an object, not a promise
      if(options.form){
        lang.forIn(options.form, function(value, name){
          params.pairs.push([name, value]);
        });
      }
      if(options.oauth){
        lang.forIn(options.oauth, function(value, name){
          if(name !== "oauth_token" && name !== "oauth_version"){
            params.pairs.push([name, value]);
            params.oauth[name] = value;
          }
        });
      }
      params.pairs.push(
        ["oauth_consumer_key", params.oauth.oauth_consumer_key = this.id],
        ["oauth_signature_method", params.oauth.oauth_signature_method = this.signatureMethod],
        ["oauth_timestamp", params.oauth.oauth_timestamp = this._getTimestamp()],
        ["oauth_nonce", params.oauth.oauth_nonce = this._generateNonce()]
      );
      if(this.token){
        params.pairs.push(["oauth_token", params.oauth.oauth_token = this.token]);
      }
      if(this.version){
        params.pairs.push(["oauth_version", params.oauth.oauth_version = this.version]);
      }

      return params;
    },

    _normalizeParams: function(pairs){
      // Encode, sort, concatenate
      return pairs.map(function(pair){ return pair.map(encodeRfc3986); }).sort(function(a, b){
        if(a[0] === b[0]){
          return a[1] < b[1] ? -1 : 1;
        }else{
          return a[0] < b[0] ? -1 : 1;
        }
      }).map(function(pair){ return pair.join("="); }).join("&");
    },

    _createSignatureBase: function(requestMethod, baseUri, params){
      return [requestMethod, baseUri, params].map(encodeRfc3986).join("&");
    },

    _signRequest: function(options){
      // Determine base URI
      var baseUri = this._buildBaseUri(options);

      // Collect all OAuth and other parameters that need to be signed
      var params = this._collectParams(options);

      // Encode and sort the parameters into the parameter string
      var paramStr = this._normalizeParams(params.pairs);

      // Build the base string
      var baseString = this._createSignatureBase(options.method, baseUri, paramStr);
      // And get the signature
      params.oauth.oauth_signature = this._createSignature(baseString);

      // Build up the authorization header using the oauth parameters
      options.headers.authorization = "OAuth " + Object.keys(params.oauth).map(function(name){
        return encodeRfc3986(name) + "=\"" + encodeRfc3986(params.oauth[name]) + "\"";
      }).join(",");
    },

    request: function(kwargs){
      var options = http.normalizeOptions(kwargs || {});
      options.oauth = kwargs.oauth;
      this._signRequest(options);
      return request(options);
    },

    obtainTempCredentials: function(kwargs){
      kwargs = kwargs || {};

      var oauth = {};
      if(kwargs.callback){
        oauth.oauth_callback = kwargs.callback;
      }else if(this.callback){
        oauth.oauth_callback = this.callback;
      }

      var endpoint = this._resolveEndpoint(kwargs.endpoint || this._normalizedTempCredentialsEndpoint);
      endpoint.method = "POST";
      endpoint.headers.accept = "application/x-www-form-urlencoded";
      endpoint.oauth = oauth;
      if(kwargs.form){
        endpoint.form = kwargs.form;
      }

      return this.request(endpoint).then(function(response){
        if(response.status !== 200){
          response.body.destroy();
          throw new errors.OAuthError();
        }

        return response.body.parseForm();
      });
    },

    obtainTokenCredentials: function(kwargs){
      kwargs = kwargs || {};

      var endpoint = this._resolveEndpoint(kwargs.endpoint || this._normalizedTokenCredentialsEndpoint);
      endpoint.method = "POST";
      endpoint.headers.accept = "application/x-www-form-urlencoded";
      endpoint.oauth = { oauth_verifier: kwargs.verifier };
      if(kwargs.form){
        endpoint.form = kwargs.form;
      }

      return this.bind({
        token: kwargs.token,
        secret: kwargs.secret
      }).request(endpoint).then(function(response){
        if(response.status !== 200){
          response.body.destroy();
          throw new errors.OAuthError();
        }

        return response.body.parseForm();
      });
    },

    bind: function(kwargs){
      var bound = Object.create(this);
      bound.token = kwargs.token;
      bound._createSignature = bound._createSignature.bind(bound, kwargs.secret);
      return bound;
    }
  });
});
