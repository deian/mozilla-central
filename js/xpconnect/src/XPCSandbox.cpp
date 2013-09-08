/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Assertions.h"
#include "xpcprivate.h"
#include "xpcpublic.h"
#include "jsfriendapi.h"
#include "mozilla/dom/Sandbox.h"
#include "mozilla/dom/Label.h"
#include "mozilla/dom/Role.h"
#include "nsIContentSecurityPolicy.h"
#include "nsDocument.h"

using namespace xpc;
using namespace JS;
using namespace mozilla;
using namespace mozilla::dom;

namespace xpc {
namespace sandbox {

#define SANDBOX_CONFIG(compartment) \
    EnsureCompartmentPrivate((compartment))->sandboxConfig

static void
SetCompartmentPrincipal(JSCompartment *compartment, nsIPrincipal *principal)
{
  JS_SetCompartmentPrincipals(compartment, nsJSPrincipals::get(principal));
}


// Turn compartment into a Sandboxed compartment. If a sandbox is provided the
// compartment sandbox is set; otherwise sandbox-mode is enabled with the
// compartment label set to the public label.
NS_EXPORT_(void)
EnableCompartmentSandbox(JSCompartment *compartment,
                         mozilla::dom::Sandbox *sandbox)
{
  MOZ_ASSERT(compartment);

  if (IsCompartmentSandboxed(compartment))
    return;

  if (sandbox) {
    SANDBOX_CONFIG(compartment).SetSandbox(sandbox);

    // set empty privileges

    nsRefPtr<Label> privileges = new Label();
    MOZ_ASSERT(privileges);

    SANDBOX_CONFIG(compartment).SetPrivileges(privileges);
  } else { // sandbox-mode
    nsRefPtr<Label> privacy = new Label();
    MOZ_ASSERT(privacy);

    nsRefPtr<Label> trust = new Label();
    MOZ_ASSERT(trust);

    SANDBOX_CONFIG(compartment).SetPrivacyLabel(privacy);
    SANDBOX_CONFIG(compartment).SetTrustLabel(trust);

    // set privileges to compartment principal

    nsCOMPtr<nsIPrincipal> privPrin;
    { // make "copy" of compartment principal
      nsresult rv;
      nsCOMPtr<nsIPrincipal> prin = GetCompartmentPrincipal(compartment);

      nsCOMPtr<nsIScriptSecurityManager> secMan =
        nsContentUtils::GetSecurityManager();
      MOZ_ASSERT(secMan);

      nsCOMPtr<nsIURI> uri;
      rv = prin->GetURI(getter_AddRefs(uri));
      MOZ_ASSERT(NS_SUCCEEDED(rv));

      rv = secMan->GetNoAppCodebasePrincipal(uri, getter_AddRefs(privPrin));
      MOZ_ASSERT(NS_SUCCEEDED(rv));
    }

    nsRefPtr<Role> privRole = new Role(privPrin);
    ErrorResult aRv;
    nsRefPtr<Label> privileges = new Label(*privRole, aRv);
    MOZ_ASSERT(privileges);

    SANDBOX_CONFIG(compartment).SetPrivileges(privileges);
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

NS_EXPORT_(void)
FreezeCompartmentSandbox(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return SANDBOX_CONFIG(compartment).Freeze();
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

  // In sandbox, no need to adjust underlying principal/policy
  // Only adjust sandbox-mode compartments
  if (!SANDBOX_CONFIG(compartment).isSandboxMode())
    return;

  nsresult rv;

  // Get privacy label and reduce it:
  nsRefPtr<Label> privacy = SANDBOX_CONFIG(compartment).GetPrivacyLabel();
  nsRefPtr<Label> privs = GetCompartmentPrivileges(compartment);
  privacy->Reduce(*privs);

  // Case 1: Empty/public label, don't loosen/impose new restrictions
  if (privacy->IsEmpty())
    return;

  nsCOMPtr<nsIPrincipal> compPrincipal = GetCompartmentPrincipal(compartment);
  MOZ_ASSERT(compPrincipal);

  // If CSP policy exists, get it
  nsCOMPtr<nsIContentSecurityPolicy> csp;
  rv = compPrincipal->GetCsp(getter_AddRefs(csp));
  MOZ_ASSERT(NS_SUCCEEDED(rv));
  // Get self uri
  nsString policy;
  nsCOMPtr<nsIURI> uri;
  rv = compPrincipal->GetURI(getter_AddRefs(uri));
  MOZ_ASSERT(NS_SUCCEEDED(rv));

  // Create a new CSP object, if none exist
  if(!csp) {
    csp = do_CreateInstance("@mozilla.org/contentsecuritypolicy;1", &rv);
    MOZ_ASSERT(NS_SUCCEEDED(rv) && csp);
    rv = compPrincipal->SetCsp(csp);
    MOZ_ASSERT(NS_SUCCEEDED(rv)); // depends on bug 886164
  }

  PrincipalArray* labelPrincipals = privacy->GetPrincipalsIfSingleton();
  bool disableStorage = false;

  if (labelPrincipals && labelPrincipals->Length() > 0) {

    // Same as as Case 1, should not really occur since we reduce
    // sandbox-mode label above
    if (MOZ_UNLIKELY(labelPrincipals->Length() == 1  &&
        labelPrincipals->ElementAt(0)->Equals(compPrincipal)))
      return;

    // Case 2: label has the form Role([a.com , b.com , ... ])
    // Allow network access to all the origins in the list, but
    // disable storage access since we can't communicate with content
    // origin.
    disableStorage = true;

    // create list of origins
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

    //XXX why was I getting the uri of the first principal??
    //rv = labelPrincipals->ElementAt(0)->GetURI(getter_AddRefs(uri));
    //MOZ_ASSERT(NS_SUCCEEDED(rv));

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
    // Swap the compartment principal with a new null principal
    compPrincipal = do_CreateInstance("@mozilla.org/nullprincipal;1", &rv);
    MOZ_ASSERT (NS_SUCCEEDED(rv));

    SetCompartmentPrincipal(compartment, compPrincipal);

    nsCOMPtr<nsIURI> baseURI;
    nsresult rv = compPrincipal->GetURI(getter_AddRefs(baseURI));
    MOZ_ASSERT(NS_SUCCEEDED(rv));

    // set the compartment location
    EnsureCompartmentPrivate(compartment)->SetLocationURI(baseURI);

    // Get the compartment global
    nsCOMPtr<nsIGlobalObject> global =
      GetNativeForGlobal(JS_GetGlobalForCompartmentOrNull(compartment));

    // Get the underlying window
    nsCOMPtr<nsIDOMWindow> win(do_QueryInterface(global));
    MOZ_ASSERT(win);

    // Get the window document
    nsCOMPtr<nsIDOMDocument> domDoc;
    win->GetDocument(getter_AddRefs(domDoc)); MOZ_ASSERT(domDoc);

    nsCOMPtr<nsIDocument> doc(do_QueryInterface(domDoc));
    MOZ_ASSERT(doc);

    // Set the document principal
    doc->SetPrincipal(compPrincipal);

    // Change the document base uri to the nullprincipal uri
    doc->SetBaseURI(baseURI);

    // Set iframe sandbox flags most restrcting flags:
    uint32_t flags =
      nsContentUtils::ParseSandboxAttributeToFlags(NS_LITERAL_STRING(""));

    doc->SetSandboxFlags(flags);

    // Set CSP since we created a new principal
    rv = compPrincipal->SetCsp(csp);
    MOZ_ASSERT(NS_SUCCEEDED(rv)); // depends on bug 886164
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

// This function gets a copy of the compartment privileges.
// IMPORTANT: the label corresponding to the privilege should NOT be
// cached, since the content principals change and thus privileges are
// "revoked".
NS_EXPORT_(already_AddRefed<mozilla::dom::Label>)
GetCompartmentPrivileges(JSCompartment*compartment)
{
  ErrorResult aRv;

  nsRefPtr<Label> privs = SANDBOX_CONFIG(compartment).GetPrivileges();
  privs = privs->Clone(aRv);

  if (aRv.Failed())
    privs = new Label(); // empty privileges

  return privs.forget();
}

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
          mozilla::dom::Label &privacy, mozilla::dom::Label &trust,
          mozilla::dom::Label *aPrivs)
{
  ErrorResult aRv;

  nsRefPtr<Label> privs = aPrivs ? aPrivs : new Label();

  nsRefPtr<mozilla::dom::Label> compPrivacy =
    xpc::sandbox::GetCompartmentPrivacyLabel(compartment);
  nsRefPtr<mozilla::dom::Label> compTrust =
    xpc::sandbox::GetCompartmentTrustLabel(compartment);

  // If any of the labels are missing, don't allow the information flow
  if (!compPrivacy || !compTrust)
    return false;


  // <privacy,trust> [=_privs <compPrivacy,compTrust>
  if (compPrivacy->Subsumes(*privs, privacy) && 
      trust.Subsumes(*privs, *compTrust))
    return true;

  // Compartment cannot directly read data, see if we can taint be to
  // allow it to read.

  nsRefPtr<mozilla::dom::Label> clrPrivacy =
    xpc::sandbox::GetCompartmentPrivacyClearance(compartment);
  nsRefPtr<mozilla::dom::Label> clrTrust   =
    xpc::sandbox::GetCompartmentTrustClearance(compartment);

  bool sandboxMode = SANDBOX_CONFIG(compartment).isSandboxMode();

  if ((sandboxMode && !clrPrivacy && !clrTrust) || 
      // in sandbox-mode without clearance
      (clrPrivacy->Subsumes(*privs,privacy) && 
       trust.Subsumes(*privs, *clrTrust)))
      // <privacy,trust> [=_privs <clrPrivacy,clrTrust>
  {
    // Label of object is not above clearance (if clearance is set),
    // so raise compartment label to allow the read.

    // join privacy
    compPrivacy->_And(privacy, aRv); 
    NS_ASSERTION(!aRv.Failed(), "internal _And clone failed.");
    if (aRv.Failed()) return false;
    //TODO: compPrivacy->Reduce(*privs);

    // join trust
    compTrust->_Or(trust, aRv);
    NS_ASSERTION(!aRv.Failed(), "internal _Or clone failed.");
    if (aRv.Failed()) return false;
    //TODO: compTrust->Reduce(*privs);

    AdjustSecurityPerimeter(compartment);

    return true;
  } 

  return false;
}

// Check if information can flow from compartment |source| to
// compartment |compartment|. If reading from a sandbox, the sandbox
// label is used; otherwise the current compartment label is used.
// For this to be safe we must not allow a compartment to read the
// label of a non-sandbox, i.e., sandbox-mode, compartment.
NS_EXPORT_(bool)
GuardRead(JSCompartment *compartment, JSCompartment *source, bool isRead)
{
  //isRead = true:  compartment is reading from source
  //isRead = false: source is writing to compartment


  //No information exchange between a non-sandboxed and sandboxed compartment
  if (!sandbox::IsCompartmentSandboxed(source))
    return false;

  if (!sandbox::IsCompartmentSandboxed(compartment))
    sandbox::EnableCompartmentSandbox(compartment);

  bool sandbox = sandbox::IsCompartmentSandbox(source);

  // When reading from sandbox, use the sandbox label, which is the
  // clearance.
  nsRefPtr<mozilla::dom::Label> privacy =
    sandbox ? xpc::sandbox::GetCompartmentPrivacyClearance(source)
            : xpc::sandbox::GetCompartmentPrivacyLabel(source);
  nsRefPtr<mozilla::dom::Label> trust =
    sandbox ? xpc::sandbox::GetCompartmentTrustClearance(source)
            : xpc::sandbox::GetCompartmentTrustLabel(source);

  if (!privacy || !trust) return false;

  nsRefPtr<Label> privs = isRead ?
                          GetCompartmentPrivileges(compartment):
                          GetCompartmentPrivileges(source);

  return GuardRead(compartment, *privacy, *trust, privs);
}

#undef SANDBOX_CONFIG

}; // sandbox
}; // xpc

