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
#include "nsIContentSecurityPolicy.h"

using namespace xpc;
using namespace JS;
using namespace mozilla;
using namespace mozilla::dom;

namespace xpc {
namespace sandbox {

static void
SetCompartmentPrincipal(JSCompartment *compartment, nsIPrincipal *principal)
{
  //TODO: JS_SetCompartmentPrincipals(compartment, nsJSPrincipals::get(principal));
}


#define SANDBOX_CONFIG(compartment) \
    EnsureCompartmentPrivate((compartment))->sandboxConfig


// Turn compartment into a Sandboxed compartment. If a sandbox is provided the
// compartment sandbox is set; otherwise sandbox-mode is enabled with the
// compartment label iset to the public label.
NS_EXPORT_(void)
EnableCompartmentSandbox(JSCompartment *compartment,
                         mozilla::dom::Sandbox *sandbox)
{
  MOZ_ASSERT(compartment);

  if (IsCompartmentSandboxed(compartment))
    return;

  if (sandbox) {
    SANDBOX_CONFIG(compartment).SetSandbox(sandbox);
  } else { /* sandbox-mode */
    nsRefPtr<Label> privacy = new Label();
    MOZ_ASSERT(privacy);

    nsRefPtr<Label> trust = new Label();
    MOZ_ASSERT(trust);

    SANDBOX_CONFIG(compartment).SetPrivacyLabel(privacy);
    SANDBOX_CONFIG(compartment).SetTrustLabel(trust);
  }
}

NS_EXPORT_(bool)
IsCompartmentSandboxed(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return SANDBOX_CONFIG(compartment).Enabled();
}

NS_EXPORT_(bool)
IsCompartmentSandbox(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return SANDBOX_CONFIG(compartment).isSandbox();
}

NS_EXPORT_(bool)
IsCompartmentSandboxMode(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return SANDBOX_CONFIG(compartment).isSandboxMode();
}

// This function adjusts the "security permieter".
// Specifically, it adjusts:
// 1. The CSP policy to restrict with whom the current compartment may
// network-communicate with.
// 2. The compartment principal to restrict writing to storage
// cnannels.
//
static void
AdjustSecurityPerimeter(JSCompartment *compartment)
{
  nsresult rv;

  nsRefPtr<Label> privacy =
    SANDBOX_CONFIG(compartment).GetPrivacyLabel();

  // Case 1: Empty/public label, don't loosen/impose new restrictions
  if (privacy->IsEmpty())
    return;

  nsIPrincipal *compPrincipal = GetCompartmentPrincipal(compartment);
  MOZ_ASSERT(compPrincipal);

  PrincipalArray* labelPrincipals =
    privacy->GetPrincipalsIfSingleton();

  bool disableStorage = false;

  // If CSP policy exists, get it
  nsCOMPtr<nsIContentSecurityPolicy> csp;
  rv = compPrincipal->GetCsp(getter_AddRefs(csp));
  MOZ_ASSERT(NS_SUCCEEDED(rv));
  // Get self uri
  nsString policy;
  nsCOMPtr<nsIURI> uri;
  rv = compPrincipal->GetURI(getter_AddRefs(uri));
  MOZ_ASSERT(NS_SUCCEEDED(rv));

  // Create a new CSP object
  if(!csp) {
    csp = do_CreateInstance("@mozilla.org/contentsecuritypolicy;1", &rv);
    MOZ_ASSERT(NS_SUCCEEDED(rv) && csp);
    rv = compPrincipal->SetCsp(csp);
    //FIXME: nullprincipals: MOZ_ASSERT(NS_SUCCEEDED(rv));
  }

  if (labelPrincipals && labelPrincipals->Length() > 0) {

    // Same as as Case 1, should not really occur since we always reduce
    // sandbox-mode compartment labels
    if (MOZ_UNLIKELY(labelPrincipals->Length() == 1  &&
        labelPrincipals->ElementAt(0)->Equals(compPrincipal)))
      return;

    // Case 2: label has the form Role([a.com , b.com , ... ])
    // Allow network access to all the origins in the list, but
    // disable storage access since we can't communicate with content
    // origin.
    disableStorage = true;

    nsString origins;
    for (unsigned i = 0; i < labelPrincipals->Length(); ++i) {
      char *origin = NULL;
      rv = labelPrincipals->ElementAt(i)->GetOrigin(&origin);
      MOZ_ASSERT(NS_SUCCEEDED(rv));
      AppendASCIItoUTF16(origin, origins);
      NS_Free(origin);
      origins.Append(NS_LITERAL_STRING(" "));
    }

    policy = NS_LITERAL_STRING("default-src ")  + origins
           + NS_LITERAL_STRING(";script-src ")  + origins
           + NS_LITERAL_STRING(";object-src ")  + origins
           + NS_LITERAL_STRING(";style-src ")   + origins
           + NS_LITERAL_STRING(";img-src ")     + origins
           + NS_LITERAL_STRING(";media-src ")   + origins
           + NS_LITERAL_STRING(";frame-src ")   + origins
           + NS_LITERAL_STRING(";font-src ")    + origins
           + NS_LITERAL_STRING(";connect-src ") + origins
           + NS_LITERAL_STRING(";");

    rv = labelPrincipals->ElementAt(0)->GetURI(getter_AddRefs(uri));
    MOZ_ASSERT(NS_SUCCEEDED(rv));

  } else {
    // Case 3: not the empty label or singleton disjunctive role
    // Disable all network and storage access
    disableStorage = true;

    // Policy to disable all communication
    policy = NS_LITERAL_STRING("default-src 'none';\
                                script-src  'none';\
                                object-src  'none';\
                                style-src   'none';\
                                img-src     'none';\
                                media-src   'none';\
                                frame-src   'none';\
                                font-src    'none';\
                                connect-src 'none';");
  }

  // Refine policy
  csp->RefinePolicy(policy, uri, true);


  if (disableStorage) {
    nsCOMPtr<nsIPrincipal> nullPrincipal =
      do_CreateInstance("@mozilla.org/nullprincipal;1", &rv);
    MOZ_ASSERT (NS_SUCCEEDED(rv));
    SetCompartmentPrincipal(compartment, nullPrincipal);
  }
}


#define DEFINE_SET_LABEL(name)                                    \
  NS_EXPORT_(void)                                                \
  SetCompartment##name(JSCompartment *compartment,                \
                      mozilla::dom::Label *aLabel)                \
  {                                                               \
    MOZ_ASSERT(compartment);                                      \
    MOZ_ASSERT(aLabel);                                           \
                                                                  \
    NS_ASSERTION(IsCompartmentSandboxed(compartment),             \
                 "Must call EnableCompartmentSandbox() first");   \
    if (!IsCompartmentSandboxed(compartment))                     \
      return;                                                     \
                                                                  \
    ErrorResult aRv;                                              \
    nsRefPtr<Label> label = (aLabel)->Clone(aRv);                 \
                                                                  \
    MOZ_ASSERT(!(aRv).Failed());                                  \
    SANDBOX_CONFIG(compartment).Set##name(label);                 \
  }

#define DEFINE_GET_LABEL(name)                                    \
  NS_EXPORT_(already_AddRefed<mozilla::dom::Label>)               \
  GetCompartment##name(JSCompartment *compartment)                \
  {                                                               \
    MOZ_ASSERT(compartment);                                      \
    return SANDBOX_CONFIG(compartment).Get##name();               \
  }

// This function sets the compartment privacy label. It clones the given label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the privacy label to a label that
// subsumes the "current label".
DEFINE_SET_LABEL(PrivacyLabel)
DEFINE_GET_LABEL(PrivacyLabel)

// This function sets the compartment trust label. It clones the given label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the trust label to a label subsumed by
// the "current label".
DEFINE_SET_LABEL(TrustLabel)
DEFINE_GET_LABEL(TrustLabel)

// This function sets the compartment privacy clearance. It clones the given
// label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the privacy clearance to a label that subsumes
// the privacy label.
DEFINE_SET_LABEL(PrivacyClearance)
DEFINE_GET_LABEL(PrivacyClearance)

// This function sets the compartment trust clearance. It clones the given
// label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the trust clearance to a label subsumed by the
// trust label.
DEFINE_SET_LABEL(TrustClearance)
DEFINE_GET_LABEL(TrustClearance)

#undef DEFINE_SET_LABEL
#undef DEFINE_GET_LABEL

NS_EXPORT_(mozilla::dom::Sandbox*)
GetCompartmentSandbox(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return SANDBOX_CONFIG(compartment).GetSandbox();
}
    
// Check if information can flow from an object labeled with |privacy|
// and |trust| into the compartment. For this to hold, the compartment
// must preserve privacy, i.e., the compartment privacy label must
// subsume the object privacy labe, and not be corrupted, i.e., the
// object trust label must be at least as trustworthy as the
// compartment trust label.
NS_EXPORT_(bool)
GuardRead(JSCompartment *compartment,
          mozilla::dom::Label &privacy, mozilla::dom::Label &trust)
{
  nsIPrincipal *priv = nullptr;
  bool sandboxMode = SANDBOX_CONFIG(compartment).isSandboxMode();

  // If the compartment is not a sandbox (it's content) and so we
  // should treat the principal as a privilege
  if (sandboxMode)
    priv = GetCompartmentPrincipal(compartment);

  nsRefPtr<mozilla::dom::Label> compPrivacy =
    xpc::sandbox::GetCompartmentPrivacyLabel(compartment);
  nsRefPtr<mozilla::dom::Label> compTrust =
    xpc::sandbox::GetCompartmentTrustLabel(compartment);

  // If any of the labels are missing, don't allow the information flow
  if (!compPrivacy || !compTrust)
    return false;

  // <privacy,trust> [=_priv <compPrivacy,compTrust>
  if (compPrivacy->Subsumes(priv, privacy) && trust.Subsumes(priv, *compTrust))
    return true;

  // Compartment cannot directly read data, see if we can taint be to
  // allow it to read.

  nsRefPtr<mozilla::dom::Label> clrPrivacy =
    xpc::sandbox::GetCompartmentPrivacyClearance(compartment);
  nsRefPtr<mozilla::dom::Label> clrTrust   =
    xpc::sandbox::GetCompartmentTrustClearance(compartment);


  if ((sandboxMode && !clrPrivacy && !clrTrust) || 
      // in sandbox-mode without clearance
      (clrPrivacy->Subsumes(priv, privacy) && trust.Subsumes(priv, *clrTrust)))
      // <privacy,trust> [=_priv <clrPrivacy,clrTrust>
  {

    // Label of object is not above clearance (if clearance is set),
    // so raise compartment label to allow the read.
    ErrorResult aRv;

    // join privacy
    compPrivacy->_And(privacy, aRv); 
    NS_ASSERTION(!aRv.Failed(), "internal _And clone failed.");
    if(aRv.Failed()) return false;
    compPrivacy->Reduce(priv);

    // join trust
    compTrust->_Or(trust, aRv);
    NS_ASSERTION(!aRv.Failed(), "internal _Or clone failed.");
    if(aRv.Failed()) return false;
    compTrust->Reduce(priv);

    AdjustSecurityPerimeter(compartment);

    return true;
  } 

  return false;
}

// Check if information can flow from compartment |source| to
// compartment |compartment|. If reading from a sandbox, the sandbox
// label is used; otherwise the current compartment label is used.
// For this to be safe we must not allow a comartment to read the
// label of a non-sandbox, i.e., sandbox-mode, compartment.
NS_EXPORT_(bool)
GuardRead(JSCompartment *compartment, JSCompartment *source)
{


  //No information exchange between a non-sandboxed and sandboxed compartment
  if (!xpc::sandbox::IsCompartmentSandboxed(source))
    return false;

  if (!xpc::sandbox::IsCompartmentSandboxed(compartment))
    xpc::sandbox::EnableCompartmentSandbox(compartment);

  bool sandbox = SANDBOX_CONFIG(source).isSandbox();
  
  // When reading from sandbox, use the sandbox label, which is the
  // clearance.
  nsRefPtr<mozilla::dom::Label> priv =
    sandbox ? xpc::sandbox::GetCompartmentPrivacyClearance(source)
            : xpc::sandbox::GetCompartmentPrivacyLabel(source);
  nsRefPtr<mozilla::dom::Label> trust =
    sandbox ? xpc::sandbox::GetCompartmentTrustClearance(source)
            : xpc::sandbox::GetCompartmentTrustLabel(source);

  if (!priv || !trust) return false;

  return GuardRead(compartment, *priv, *trust);
}

#undef SANDBOX_CONFIG

}; // sandbox
}; // xpc

