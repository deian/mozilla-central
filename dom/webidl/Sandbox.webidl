/* -*- Mode: IDL; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 */

interface Principal;

[Constructor,
 Constructor(Label privacy),
 Constructor(Label privacy, Label trust)
 ]
interface Sandbox {

  // Schedule code in the sandbox
  [Throws] void schedule(DOMString src);

  // Sandbox privacy and trust labels
  [Pure] readonly attribute Label privacy;
  [Pure] readonly attribute Label trust;

  // Was the sandbox used?
  readonly attribute boolean isClean;

  // Read message from sandbox
  [Throws] void ondone(EventHandler successHandler,
                       optional EventHandler errorHandler);

  // Send message to sandbox
  [Throws] void postMessage(any message);

  // Read sandbox result
  [GetterThrows] readonly attribute any result;

  // Grant sandbox ownership of fresh principal
  void grant(FreshPrincipal principal);

  // Static ==================================================================
  //TODO: move into partial interface

  // Enable sandbox for compartment, if not enabled.
  static void enableSandbox();


  // Check if current compartment is sandboxed
  static boolean isSandboxed();
  static boolean isSandbox();
  static boolean isSandboxMode();

  // Frozen sandbox labels cannto change
  [Throws] static void freeze();
  [Throws] static boolean isFrozen();

  // label

  // Get the underlying privacy label
  static Label? getPrivacyLabel();
  // Set the underlying privacy label, if it subsumes the existing one
  [Throws] static void setPrivacyLabel(Label aLabel);

  // Get the underlying trust label
  static Label? getTrustLabel();
  // Set the underlying trust label, if the existing one subsumes it
  [Throws] static void setTrustLabel(Label aLabel);

  // clearance

  // Get the underlying privacy clearance
  static Label? getPrivacyClearance();
  // Set the underlying trust clearance, if the existing one subsumes it
  [Throws] static void setPrivacyClearance(Label aLabel);

  // Get the underlying trust clearance
  static Label? getTrustClearance();
  // Set the underlying privacy clearance, if it subsumes the existing one
  [Throws] static void setTrustClearance(Label aLabel);

  // Get the compartment principal
  static DOMString getPrincipal();

  // Add principal to ownership list
  static void own(FreshPrincipal principal);


  // Get principals owned by compartment
  //sequence<Principal> getOwnedFreshPrincipals();

  // privileges

  // Get the underlying privileges
  static Label? getPrivileges();

  // Static ==================================================================

  // temporary*********************************************************
  readonly attribute object getSandbox;


};

[NoInterfaceObject]
interface SandboxEventTarget : EventTarget {
  [SetterThrows] attribute EventHandler onmessage;
};
