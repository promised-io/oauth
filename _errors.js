if (typeof define !== 'function') { var define = (require('amdefine'))(module); }

define([
  "exports",
  "promised-io/lib/errorFactory"
], function(exports, errorFactory){
  "use strict";

  exports.OAuthError = errorFactory("OAuthError", "An error occured in the OAuth flow.");
});
