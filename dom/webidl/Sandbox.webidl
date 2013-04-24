/* -*- Mode: IDL; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 */

callback SandboxCallback = void (any message);

[Constructor,
 Constructor(Label privacy),
 Constructor(Label privacy, Label trust)
 ]
interface Sandbox {

  //boolean subsumes(Sandbox other);

  [Throws] void schedule(DOMString src);

  [Pure] readonly attribute Label privacy;

  [Pure] readonly attribute Label trust;

  // Was the sandbox used?
  readonly attribute boolean isClean;

  // Read message from sandbox
  [Throws] void ondone(EventHandler successHandler,
                       optional EventHandler errorHandler);

  // Send message to sandbox
  [Throws] void postMessage(any message);

  // Static ==================================================================
  //TODO: move into partial interface

  // Enable sandbox for compartment, if not enabled.
  static void enableSandbox();
  // Check if current compartment is sandboxed
  static boolean isSandboxed();

  // label

  // Get the underlying privacy label
  static Label? getPrivacyLabel();
  // Set the underlying privacy label, if it subsumes the existing one
  [Throws] static boolean setPrivacyLabel(Label aLabel);

  // Get the underlying trust label
  static Label? getTrustLabel();
  // Set the underlying trust label, if the existing one subsumes it
  [Throws] static boolean setTrustLabel(Label aLabel);

  // clearance

  // Get the underlying privacy clearance
  static Label? getPrivacyClearance();
  // Set the underlying trust clearance, if the existing one subsumes it
  [Throws] static boolean setPrivacyClearance(Label aLabel);

  // Get the underlying trust clearance
  static Label? getTrustClearance();
  // Set the underlying privacy clearance, if it subsumes the existing one
  [Throws] static boolean setTrustClearance(Label aLabel);

  // Static ==================================================================

  // temporary:
  readonly attribute object getSandbox;

  // temporary:
  [GetterThrows]
  readonly attribute any result;
  
};

[NoInterfaceObject]
interface SandboxEventTarget : EventTarget {
  [SetterThrows] attribute EventHandler onmessage;
};

