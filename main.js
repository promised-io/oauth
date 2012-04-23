if (typeof define !== 'function') { var define = (require('amdefine'))(module); }

define([
  "./_errors",
  "./Client"
], function(errors ,Client){
  "use strict";

  return {
    OAuthError: errors.OAuthError,
    Client: Client
  };
});
