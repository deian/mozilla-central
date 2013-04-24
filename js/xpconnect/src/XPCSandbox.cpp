/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Assertions.h"
#include "xpcprivate.h"
#include "xpcpublic.h"
#include "jsfriendapi.h"
#include  "mozilla/dom/Sandbox.h"
#include  "mozilla/dom/Label.h"
#include  "mozilla/dom/Role.h"

using namespace xpc;
using namespace JS;
using namespace mozilla;
using namespace mozilla::dom;

namespace xpc {
namespace sandbox {

#define SET_LABEL_BEGIN                                           \
  do {                                                            \
    MOZ_ASSERT((compartment));                                    \
    MOZ_ASSERT((aLabel));                                         \
                                                                  \
    if (!IsSandboxedCompartment((compartment))) {                 \
      NS_ASSERTION(IsSandboxedCompartment((compartment)),         \
          "Must call enableCompartmentSandbox() first");          \
      return;                                                     \
    }                                                             \
                                                                  \
    ErrorResult aRv;                                              \
    nsRefPtr<Label> label = (aLabel)->Clone(aRv);                 \
                                                                  \
    MOZ_ASSERT(!(aRv).Failed());                                  \

#define SET_LABEL_END                                             \
  } while(0);

#define COMPARTMENT_LABELS(compartment) \
    EnsureCompartmentPrivate((compartment))->labels

// This function sets the compartment privacy label. It clones the given label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the privacy label to a label that subsumes the
// "current label".
NS_EXPORT_(void)
SetCompartmentPrivacyLabel(JSCompartment *compartment, 
                          mozilla::dom::Label *aLabel)
{
  SET_LABEL_BEGIN
    COMPARTMENT_LABELS(compartment).SetPrivacyLabel(label);
  SET_LABEL_END
}

NS_EXPORT_(already_AddRefed<mozilla::dom::Label>) 
GetCompartmentPrivacyLabel(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return COMPARTMENT_LABELS(compartment).GetPrivacyLabel();
}


// This function sets the compartment trust label. It clones the given label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the trust label to a label subsumed by the
// "current label".
NS_EXPORT_(void)
SetCompartmentTrustLabel(JSCompartment *compartment, 
                         mozilla::dom::Label *aLabel)
{
  SET_LABEL_BEGIN
    COMPARTMENT_LABELS(compartment).SetTrustLabel(label);
  SET_LABEL_END
}

NS_EXPORT_(already_AddRefed<mozilla::dom::Label>) 
GetCompartmentTrustLabel(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return COMPARTMENT_LABELS(compartment).GetTrustLabel();
}

// This function sets the compartment privacy clearance. It clones the given
// label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the privacy clearance to a label that subsumes
// the privacy label.
NS_EXPORT_(void)
SetCompartmentPrivacyClearance(JSCompartment *compartment, 
                               mozilla::dom::Label *aLabel)
{
  SET_LABEL_BEGIN
    COMPARTMENT_LABELS(compartment).SetPrivacyClearance(label);
  SET_LABEL_END
}

NS_EXPORT_(already_AddRefed<mozilla::dom::Label>) 
GetCompartmentPrivacyClearance(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return COMPARTMENT_LABELS(compartment).GetPrivacyClearance();
}

// This function sets the compartment trust clearance. It clones the given
// label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the trust clearance to a label subsumed by the
// trust label.
NS_EXPORT_(void)
SetCompartmentTrustClearance(JSCompartment *compartment, 
                             mozilla::dom::Label *aLabel)
{
  SET_LABEL_BEGIN
    COMPARTMENT_LABELS(compartment).SetTrustClearance(label);
  SET_LABEL_END
}

NS_EXPORT_(already_AddRefed<mozilla::dom::Label>) 
GetCompartmentTrustClearance(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return COMPARTMENT_LABELS(compartment).GetTrustClearance();
}

// ===========================================================================

// This function enables sandbox-mode by setting the privacy and trust labels
// to the empty label, if they haven't been set.
NS_EXPORT_(void)
EnableCompartmentSandbox(JSCompartment *compartment,
                         mozilla::dom::Sandbox *assocSandbox)
{
  MOZ_ASSERT(compartment);

  if (IsSandboxedCompartment(compartment))
    return;

  nsRefPtr<Label> privacy = new Label();
  MOZ_ASSERT(privacy);

  nsRefPtr<Label> trust = new Label();
  MOZ_ASSERT(trust);


  COMPARTMENT_LABELS(compartment).SetPrivacyLabel(privacy);
  COMPARTMENT_LABELS(compartment).SetTrustLabel(trust);
  COMPARTMENT_LABELS(compartment).SetAssocSandbox(assocSandbox);
}

NS_EXPORT_(bool)
IsSandboxedCompartment(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return COMPARTMENT_LABELS(compartment).IsSandboxedCompartment();
}

NS_EXPORT_(mozilla::dom::Sandbox*)
GetCompartmentAssocSandbox(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return COMPARTMENT_LABELS(compartment).GetAssocSandbox();
}
    

#undef COMPARTMENT_LABELS
#undef SET_LABEL_END
#undef SET_LABEL_BEGIN

// Can information flow to compartment from object labeld with privacy and trust
NS_EXPORT_(bool)
GuardRead(JSCompartment *compartment,
          mozilla::dom::Label &privacy, mozilla::dom::Label &trust)
{
  nsIPrincipal *priv = GetCompartmentPrincipal(compartment);

  nsRefPtr<mozilla::dom::Label> compPrivacy =
    xpc::sandbox::GetCompartmentPrivacyLabel(compartment);
  nsRefPtr<mozilla::dom::Label> compTrust =
    xpc::sandbox::GetCompartmentTrustLabel(compartment);

  // If any of the labels are missing, don't allow the information flow
  if (!compPrivacy || !compTrust)
    return false;

  // <privacy,trust> [=_compartment <compPrivacy,compTrust>
  if (compPrivacy->Subsumes(priv, privacy) &&
      trust.Subsumes(priv, *compTrust))
    return true;

  // Compartment cannot directly read data, see if we can taint be to allow it to read.

  nsRefPtr<mozilla::dom::Label> clrPrivacy =
    xpc::sandbox::GetCompartmentPrivacyClearance(compartment);
  nsRefPtr<mozilla::dom::Label> clrTrust   =
    xpc::sandbox::GetCompartmentTrustClearance(compartment);


  if ((!clrPrivacy && !clrTrust) || // no clearance
      // <privacy,trust> [=_compartment <clrPrivacy,clrTrust>
      (clrPrivacy->Subsumes(priv, privacy) && 
       trust.Subsumes(priv, *clrTrust))) {

    // Does not have clearance or clearance _is_ high enough.
    // raise compartment label
    ErrorResult aRv;

    // join: privacy: AND
    compPrivacy->_And(/*priv,*/privacy, aRv); 
    NS_ASSERTION(!aRv.Failed(), "internal _And clone failed.");
    if (aRv.Failed()) return false;

    // join: trust: OR
    compTrust->_Or(/*priv,*/trust, aRv);
    NS_ASSERTION(!aRv.Failed(), "internal _Or clone failed.");
    if (aRv.Failed()) return false;

    return true;
  } 
  return false;
}

// Can information flow form source to compartment
NS_EXPORT_(bool)
GuardRead(JSCompartment *compartment, JSCompartment *source)
{
  mozilla::dom::Sandbox* sbox = GetCompartmentAssocSandbox(source);
  
  nsRefPtr<mozilla::dom::Label> priv;
  nsRefPtr<mozilla::dom::Label> trust;

  if (sbox) {
    priv = sbox->Privacy();
    trust = sbox->Trust();
  } else {
    // TODO: reason about the soundness of this:
    priv = xpc::sandbox::GetCompartmentPrivacyLabel(source);
    trust = xpc::sandbox::GetCompartmentTrustLabel(source);
  }

  NS_ASSERTION(priv && trust, "sandbox does not have a privacy/trust label");
  if (!priv || !trust) return false;

  return GuardRead(compartment, *priv, *trust);

  return false;

}


} // namespace sandbox
} // namespace xpc
