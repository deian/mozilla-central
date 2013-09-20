/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");

function SandboxService() {
  this._isInitialized = false;
}

SandboxService.prototype = {
  classID:          Components.ID("{9760c598-42b3-4a65-9ae2-2dac1d453f1b}"),
  QueryInterface:   XPCOMUtils.generateQI([Ci.nsISandboxService]),
  _xpcom_categories: [ { service: true } ],
  

  get isInitialized() {
    return this._isInitialized;
  },

  set isInitialized (init) {
    this._isInitialized = init;
  },
  /**
   * Labels are expected to have the form:
   * [ [ "p1", "p2", ...] , [ "q1", "q2", ...], ...]
   */
  _parseLabel: function(win, jsonLabel) {
    var label = new win.Label();
    var formatErr = 
      'Label expected to be a JSON value: [ [ "p1", "p2", ...] , [ "q1", "q2", ...], ...]';
    var clauses = JSON.parse(jsonLabel);
    if (!Array.isArray(clauses)) { throw formatErr; }
    for (var i = 0; i < clauses.length; i++) {
      var disjs = clauses[i];
      if (!Array.isArray(disjs)) { throw formatErr; }
      label.and(new win.Role(disjs)); 
    }
    return label;
  },
  init : function(win, jsonLabel) {
    win.console.log("Got JSON label: "+jsonLabel);
    if (this._isInitialized)
      return false;

    try {
      var label = this._parseLabel(win, jsonLabel);
      win.Sandbox.enableSandbox();
      win.Sandbox.setPrivacyLabel(label);
      this._isInitialized = true;
      win.console.log("Initialized sandbox-mode: "+label);
      return true;
    } catch(e) {
      win.console.log("Failed to initialize Sandbox: "+e);
      return false;
    }
  }
};

var components = [SandboxService];
this.NSGetFactory = XPCOMUtils.generateNSGetFactory([SandboxService]);
