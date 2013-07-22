/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/dom/Sandbox.h"
#include "mozilla/dom/RoleBinding.h"
#include "mozilla/dom/LabelBinding.h"
#include "mozilla/dom/SandboxBinding.h"
#include "nsContentUtils.h"
#include "nsIContentSecurityPolicy.h"
#include "nsEventDispatcher.h"
#include "xpcprivate.h"
#include "xpccomponents.h"
#include "mozilla/dom/StructuredCloneUtils.h"

namespace mozilla {
namespace dom {

#define SANDBOX_CONFIG(compartment) \
  xpc::EnsureCompartmentPrivate((compartment))->sandboxConfig

// Helper for getting JSObject* from GlobalObject (without casting .Get())
static JSObject* getGlobalJSObject(const GlobalObject& global);
//Helper for setting the ErrorResult to a string
static void JSErrorResult(JSContext *cx, ErrorResult& aRv, const char *msg);

////////////////////////////////

// SandboxEventTarget:

NS_IMPL_CYCLE_COLLECTION_TRAVERSE_BEGIN_INHERITED(SandboxEventTarget,
                                                  nsDOMEventTargetHelper)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE_SCRIPT_OBJECTS
NS_IMPL_CYCLE_COLLECTION_TRAVERSE_END

NS_IMPL_CYCLE_COLLECTION_UNLINK_BEGIN_INHERITED(SandboxEventTarget,
                                                nsDOMEventTargetHelper)
  NS_IMPL_CYCLE_COLLECTION_UNLINK_PRESERVED_WRAPPER
NS_IMPL_CYCLE_COLLECTION_UNLINK_END

NS_IMPL_CYCLE_COLLECTION_TRACE_BEGIN_INHERITED(SandboxEventTarget,
                                               nsDOMEventTargetHelper)
  NS_IMPL_CYCLE_COLLECTION_TRACE_PRESERVED_WRAPPER
NS_IMPL_CYCLE_COLLECTION_TRACE_END

NS_INTERFACE_MAP_BEGIN_CYCLE_COLLECTION_INHERITED(SandboxEventTarget)
  NS_WRAPPERCACHE_INTERFACE_MAP_ENTRY
NS_INTERFACE_MAP_END_INHERITING(nsDOMEventTargetHelper)

NS_IMPL_ADDREF_INHERITED(SandboxEventTarget, nsDOMEventTargetHelper)
NS_IMPL_RELEASE_INHERITED(SandboxEventTarget, nsDOMEventTargetHelper)


// Sandbox:

NS_IMPL_CYCLE_COLLECTION_TRAVERSE_BEGIN_INHERITED(Sandbox,
                                                  nsDOMEventTargetHelper)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mPrivacy)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mTrust)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mCurrentPrivacy)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mCurrentTrust)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mPrincipal)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mEventTarget)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE_SCRIPT_OBJECTS
NS_IMPL_CYCLE_COLLECTION_TRAVERSE_END

NS_IMPL_CYCLE_COLLECTION_UNLINK_BEGIN_INHERITED(Sandbox,
                                                nsDOMEventTargetHelper)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mPrivacy)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mTrust)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mCurrentPrivacy)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mCurrentTrust)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mPrincipal)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mEventTarget)
  NS_IMPL_CYCLE_COLLECTION_UNLINK_PRESERVED_WRAPPER
  tmp->Destroy();
NS_IMPL_CYCLE_COLLECTION_UNLINK_END

NS_IMPL_CYCLE_COLLECTION_TRACE_BEGIN_INHERITED(Sandbox,
                                               nsDOMEventTargetHelper)
  NS_IMPL_CYCLE_COLLECTION_TRACE_PRESERVED_WRAPPER
  NS_IMPL_CYCLE_COLLECTION_TRACE_JS_MEMBER_CALLBACK(mSandboxObj)
  NS_IMPL_CYCLE_COLLECTION_TRACE_JSVAL_MEMBER_CALLBACK(mResult)
  NS_IMPL_CYCLE_COLLECTION_TRACE_JSVAL_MEMBER_CALLBACK(mMessage)
NS_IMPL_CYCLE_COLLECTION_TRACE_END

NS_INTERFACE_MAP_BEGIN_CYCLE_COLLECTION_INHERITED(Sandbox)
  NS_WRAPPERCACHE_INTERFACE_MAP_ENTRY
NS_INTERFACE_MAP_END_INHERITING(nsDOMEventTargetHelper)

NS_IMPL_ADDREF_INHERITED(Sandbox, nsDOMEventTargetHelper)
NS_IMPL_RELEASE_INHERITED(Sandbox, nsDOMEventTargetHelper)

////////////////////////////////

Sandbox::Sandbox()
  : mPrivacy(new Label())
  , mTrust(new Label())
  , mCurrentPrivacy(nullptr)
  , mCurrentTrust(nullptr)
  , mSandboxObj(nullptr)
  , mResult(JSVAL_VOID)
  , mResultType(ResultNone)
  , mEventTarget(nullptr)
  , mMessage(JSVAL_VOID)
  , mMessageIsSet(false)
{
  SetIsDOMBinding();
}

Sandbox::Sandbox(mozilla::dom::Label& privacy)
  : mPrivacy(&privacy)
  , mTrust(new Label())
  , mCurrentPrivacy(nullptr)
  , mCurrentTrust(nullptr)
  , mPrincipal(nullptr)
  , mSandboxObj(nullptr)
  , mResult(JSVAL_VOID)
  , mResultType(ResultNone)
  , mEventTarget(nullptr)
  , mMessage(JSVAL_VOID)
  , mMessageIsSet(false)
{
  SetIsDOMBinding();
}

Sandbox::Sandbox(mozilla::dom::Label& privacy, mozilla::dom::Label& trust)
  : mPrivacy(&privacy)
  , mTrust(&trust)
  , mCurrentPrivacy(nullptr)
  , mCurrentTrust(nullptr)
  , mPrincipal(nullptr)
  , mSandboxObj(nullptr)
  , mResult(JSVAL_VOID)
  , mResultType(ResultNone)
  , mEventTarget(nullptr)
  , mMessage(JSVAL_VOID)
  , mMessageIsSet(false)
{
  SetIsDOMBinding();
}

Sandbox::~Sandbox()
{ }

void
Sandbox::Destroy()
{
  mPrivacy = nullptr;
  mTrust = nullptr;
  mCurrentPrivacy = nullptr;
  mCurrentTrust = nullptr;
  mPrincipal = nullptr;
  mSandboxObj = nullptr;
  mResult = JSVAL_VOID;
  mEventTarget = nullptr;
  mMessage= JSVAL_VOID;

  NS_DROP_JS_OBJECTS(this, Sandbox);
}

already_AddRefed<Sandbox>
Sandbox::Constructor(const GlobalObject& global, 
                     JSContext* cx, ErrorResult& aRv)
{
  nsRefPtr<Sandbox> sandbox = new Sandbox();
  if (!sandbox) {
    aRv = NS_ERROR_OUT_OF_MEMORY;
    return nullptr;
  }
  sandbox->Init(global, cx, aRv);
  if (aRv.Failed())
    return nullptr;
  return sandbox.forget();
}

already_AddRefed<Sandbox>
Sandbox::Constructor(const GlobalObject& global,
                     JSContext* cx, 
                     mozilla::dom::Label& privacy, 
                     ErrorResult& aRv)
{
  EnableSandbox(global);
  nsRefPtr<Label> privacyCopy = privacy.Clone(aRv);
  if (aRv.Failed())
    return nullptr;

  nsRefPtr<Sandbox> sandbox = new Sandbox(*privacyCopy);
  if (!sandbox) {
    aRv = NS_ERROR_OUT_OF_MEMORY;
    return nullptr;
  }

  sandbox->Init(global, cx, aRv);

  return sandbox.forget();
}

already_AddRefed<Sandbox>
Sandbox::Constructor(const GlobalObject& global, 
                     JSContext* cx, 
                     mozilla::dom::Label& privacy, 
                     mozilla::dom::Label& trust, 
                     ErrorResult& aRv)
{
  EnableSandbox(global);
  nsRefPtr<Label> privacyCopy = privacy.Clone(aRv);
  nsRefPtr<Label> trustCopy = trust.Clone(aRv);
  if (aRv.Failed())
    return nullptr;

  nsRefPtr<Sandbox> sandbox = new Sandbox(*privacyCopy, *trustCopy);
  if (!sandbox) {
    aRv = NS_ERROR_OUT_OF_MEMORY;
    return nullptr;
  }

  sandbox->Init(global, cx, aRv);

  return sandbox.forget();
}

void
Sandbox::Schedule(JSContext* cx, const nsAString& src, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  JSCompartment *compartment = js::GetContextCompartment(cx);
  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  MOZ_ASSERT(privs);

  nsRefPtr<Label> callerP =
    xpc::sandbox::GetCompartmentPrivacyLabel(compartment);
  nsRefPtr<Label> callerT =
    xpc::sandbox::GetCompartmentTrustLabel(compartment);

  if (MOZ_UNLIKELY(!xpc::sandbox::IsCompartmentSandboxed(compartment))) {
    //If we somehow ended up with a Sandbox object but are not in a 
    //compartment that is not a sandbox/sandbox-mode

    // enable sandbox-mode
    xpc::sandbox::EnableCompartmentSandbox(compartment);

    //set the initial label of the sandbox to this compartments labels
    callerP = xpc::sandbox::GetCompartmentPrivacyLabel(compartment);
    callerT = xpc::sandbox::GetCompartmentTrustLabel(compartment);
    if (!callerP || !callerT) {
      JSErrorResult(cx, aRv, "Cannot enable sandbox mode");
      return;
    }
  }

  // if this is the first time we're scheduling code in the sandbox,
  // start with an initial label set to the current compartment's
  // labels (though we must check that these labels flow to the labels
  // of the sandbox)
  if (!mCurrentPrivacy && !mCurrentTrust) {
    mCurrentPrivacy = callerP->Clone(aRv);
    if (aRv.Failed()) {
      JSErrorResult(cx, aRv, "Cannot set initial privacy label");
      return;
    }
    mCurrentTrust = callerT->Clone(aRv);
    if (aRv.Failed()) {
      JSErrorResult(cx, aRv, "Cannot set initial trust label");
      return;
    }
  }

  // current compartment label must flow to label of sandbox
  if (!mPrivacy->Subsumes(*privs, *callerP) ||
      !callerT->Subsumes(*privs, *mTrust)) {
    JSErrorResult(cx, aRv, "Cannot execute code in a less sensitive sandbox");
    return;
  }

  // It is required that EvalInSandbox not raise the current labels
  // above the sandbox labels; otherwise we must perform an additional
  // check as the first step in the sandbox

  EvalInSandbox(cx, src,aRv);
}


bool
Sandbox::IsClean() const
{
  return !mCurrentPrivacy && !mCurrentTrust;
}

void 
Sandbox::Ondone(JSContext* cx, EventHandlerNonNull* successHandler, 
                const Optional<nsRefPtr<EventHandlerNonNull> >& errorHandler,
                ErrorResult& aRv)
{
  aRv.MightThrowJSException();

  JSCompartment *compartment = js::GetContextCompartment(cx);


  if (MOZ_UNLIKELY(!xpc::sandbox::IsCompartmentSandboxed(compartment)))
    xpc::sandbox::EnableCompartmentSandbox(compartment);

  // raises current label
  if (!xpc::sandbox::GuardRead(compartment, *mPrivacy,*mTrust)) {
    JSErrorResult(cx, aRv, "Cannot read from sandbox.");
    return;
  }

  // set handlers

  SetOnmessage(successHandler, aRv);
  if (aRv.Failed()) return;

  if (errorHandler.WasPassed()) {
    SetOnerror(errorHandler.Value(), aRv);
    if (aRv.Failed()) return;
  }

  //dispatch handlers

  if (!DispatchResult(cx))
    aRv.Throw(NS_ERROR_FAILURE);
}

void
Sandbox::PostMessage(JSContext* cx, JS::Handle<JS::Value> message, 
                     ErrorResult& aRv)
{
  aRv.MightThrowJSException();

  // clear message
  ClearMessage();

  // Structurally clone the object
  JS::RootedValue v(cx, message);

  // Apply the structured clone algorithm
  StructuredCloneData data;
  JSAutoStructuredCloneBuffer buffer;

  if (!WriteStructuredClone(cx, v, buffer, data.mClosure)) {
    JSErrorResult(cx, aRv,
        "PostMessage: Argument must be a structurally clonable object.");
    return;
  } else {
    data.mData = buffer.data();
    data.mDataLength = buffer.nbytes();

    MOZ_ASSERT(ReadStructuredClone(cx, data, v.address())); // buffer->object
  }

  // Set the message
  SetMessage(v);

  // Dispatch event to the sandbox onmessage handler
  DispatchSandboxOnmessageEvent(aRv);
}

void
Sandbox::DispatchSandboxOnmessageEvent(ErrorResult& aRv)
{
  if (!mMessageIsSet) return;

  nsCOMPtr<nsIDOMEvent> event;
  nsresult rv = nsEventDispatcher::CreateEvent(mEventTarget, nullptr, nullptr,
                                               NS_LITERAL_STRING("Events"),
                                               getter_AddRefs(event));
  if (NS_FAILED(rv)) {
    aRv.Throw(rv);
    return;
  }

  event->InitEvent(NS_LITERAL_STRING("message"), /* canBubble = */ false,
      /* canCancel = */ false);
  event->SetTrusted(true);

  mEventTarget->DispatchDOMEvent(nullptr, event, nullptr, nullptr);
}

already_AddRefed<Label>
Sandbox::Privacy() const
{
  nsRefPtr<Label> privacy = mPrivacy;
  return privacy.forget();
}

already_AddRefed<Label>
Sandbox::Trust() const
{
  nsRefPtr<Label> trust = mTrust;
  return trust.forget();
}

already_AddRefed<Label>
Sandbox::CurrentPrivacy() const
{
  nsRefPtr<Label> privacy = mCurrentPrivacy;
  return privacy.forget();
}

// Caller should ensure that this label subsumes the current label and
// is subsumed by the sanbox label
void 
Sandbox::SetCurrentPrivacy(mozilla::dom::Label* aLabel)
{
  mCurrentPrivacy = aLabel;
}

already_AddRefed<Label>
Sandbox::CurrentTrust() const
{
  nsRefPtr<Label> trust = mCurrentTrust;
  return trust.forget();
}

// Caller should ensure that this label subsumes the sandbox label and
// is subsumed by the current label
void
Sandbox::SetCurrentTrust(mozilla::dom::Label* aLabel) 
{
  mCurrentTrust = aLabel;
}


JS::Value
Sandbox::GetResult(JSContext* cx, ErrorResult& aRv) {
  // Wrap the result
  if (!JS_WrapValue(cx, mResult.unsafeGet())) {
    JSErrorResult(cx, aRv, "Failed to wrap message.");
    return JSVAL_VOID;
  }
  return mResult;
}
void 
Sandbox::Grant(mozilla::dom::FreshPrincipal& principal)
{
  // get sandbox compartment
  //Own(glob, principal);
}


inline void
Sandbox::SetResult(JS::Handle<JS::Value> val, ResultType type)
{
  mResult = val;
  mResultType = type;
  NS_HOLD_JS_OBJECTS(this, Sandbox);
}

inline void
Sandbox::ClearResult()
{
  mResult = JSVAL_VOID;
  mResultType = ResultNone;
  NS_HOLD_JS_OBJECTS(this, Sandbox);
}

inline void
Sandbox::SetMessage(JS::Handle<JS::Value> val)
{
  mMessage = val;
  mMessageIsSet = true;
  NS_HOLD_JS_OBJECTS(this, Sandbox);
}

inline void
Sandbox::ClearMessage()
{
  mMessage = JSVAL_VOID;
  mMessageIsSet = false;
  NS_HOLD_JS_OBJECTS(this, Sandbox);
}


bool
Sandbox::SetMessageToHandle(JSContext *cx, JS::MutableHandleValue vp)
{
  // Wrap the message
  if (!JS_WrapValue(cx, mMessage.unsafeGet())) {
    ClearMessage();
    JS_ReportError(cx, "Failed to wrap message.");
    return false;
  }
  vp.set(mMessage);
  return true;
}


// Static ====================================================================

void
Sandbox::EnableSandbox(const GlobalObject& global)
{
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  xpc::sandbox::EnableCompartmentSandbox(compartment);
}

bool 
Sandbox::IsSandboxed(const GlobalObject& global)
{
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  return xpc::sandbox::IsCompartmentSandboxed(compartment);
}

bool 
Sandbox::IsSandbox(const GlobalObject& global)
{
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  return xpc::sandbox::IsCompartmentSandbox(compartment);
}

bool 
Sandbox::IsSandboxMode(const GlobalObject& global)
{
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  return xpc::sandbox::IsCompartmentSandboxMode(compartment);
}

// label

bool
Sandbox::SetPrivacyLabel(const GlobalObject& global, JSContext* cx, 
                         mozilla::dom::Label& aLabel, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  if (!IsSandboxed(global)) {
    JSErrorResult(cx, aRv, "Must enable sandbox-mode to set privacy label.");
    return false;
  }

  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));

  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  nsRefPtr<Label> currentLabel = GetPrivacyLabel(global, cx);
  if (!currentLabel) {
    JSErrorResult(cx, aRv, "Failed to get current privacy label.");
    return false;
  }

  if (!aLabel.Subsumes(*privs, *currentLabel))
    return false;

  nsRefPtr<Label> currentClearance = GetPrivacyClearance(global, cx);
  if (currentClearance && !currentClearance->Subsumes(aLabel))
    return false;

  xpc::sandbox::SetCompartmentPrivacyLabel(compartment, &aLabel);
  return true;
}

// Helper macro for retriveing the privacy/trust label/clearance
#define GET_LABEL(name)                                                   \
  do {                                                                    \
    JSCompartment *compartment =                                          \
      js::GetObjectCompartment(getGlobalJSObject(global));                \
    nsRefPtr<Label> l = xpc::sandbox::GetCompartment##name(compartment);  \
                                                                          \
    if (!l) return nullptr;                                               \
    return l.forget();                                                    \
  } while(0);

already_AddRefed<Label>
Sandbox::GetPrivacyLabel(const GlobalObject& global, JSContext* cx)
{
  GET_LABEL(PrivacyLabel);
}

bool
Sandbox::SetTrustLabel(const GlobalObject& global, JSContext* cx, 
              mozilla::dom::Label& aLabel, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  if (!IsSandboxed(global)) {
    JSErrorResult(cx, aRv, "Must enable sandbox-mode to set trust label.");
    return false;
  }

  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));

  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  nsRefPtr<Label> currentLabel = GetTrustLabel(global, cx);
  if (!currentLabel) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return false;
  }

  if (!currentLabel->Subsumes(*privs, aLabel))
    return false;

  nsRefPtr<Label> currentClearance = GetTrustClearance(global, cx);
  if (currentClearance && !aLabel.Subsumes(*currentClearance))
    return false;

  xpc::sandbox::SetCompartmentTrustLabel(compartment, &aLabel);
  return true;
}

already_AddRefed<Label>
Sandbox::GetTrustLabel(const GlobalObject& global, JSContext* cx)
{
  GET_LABEL(TrustLabel);
}

//clearance

bool
Sandbox::SetPrivacyClearance(const GlobalObject& global, JSContext* cx, 
                             mozilla::dom::Label& aLabel, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  if (!IsSandboxed(global)) {
    JSErrorResult(cx, aRv, 
                  "Must enable sandbox-mode to set privacy clearance.");
    return false;
  }

  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));

  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  nsRefPtr<Label> currentClearance = GetPrivacyClearance(global, cx);
  if (currentClearance && !currentClearance->Subsumes(*privs, aLabel))
    return false;

  nsRefPtr<Label> currentLabel = GetPrivacyLabel(global, cx);
  if (!currentLabel) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return false;
  }

  if (!aLabel.Subsumes(*currentClearance))
    return false;

  xpc::sandbox::SetCompartmentPrivacyClearance(compartment, &aLabel);
  return true;
}

already_AddRefed<Label>
Sandbox::GetPrivacyClearance(const GlobalObject& global, JSContext* cx)
{
  GET_LABEL(PrivacyClearance);
}

bool
Sandbox::SetTrustClearance(const GlobalObject& global, JSContext* cx, 
                           mozilla::dom::Label& aLabel, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  if (!IsSandboxed(global)) {
    JSErrorResult(cx, aRv, "Must enable sandbox-mode to set trust clearance.");
    return false;
  }

  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));

  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  nsRefPtr<Label> currentClearance = GetTrustClearance(global, cx);
  if (currentClearance && !aLabel.Subsumes(*privs, *currentClearance))
    return false;

  nsRefPtr<Label> currentLabel = GetTrustLabel(global, cx);
  if (!currentLabel) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return false;
  }

  if (!currentLabel->Subsumes(aLabel))
    return false;


  xpc::sandbox::SetCompartmentTrustClearance(compartment, &aLabel);
  return true;
}

already_AddRefed<Label>
Sandbox::GetTrustClearance(const GlobalObject& global, JSContext* cx)
{
  GET_LABEL(TrustClearance);
}

#undef GET_LABEL

// Get underlying freh principal privileges, which means all but the
// underlying compartment privileges
already_AddRefed<Label>
Sandbox::GetPrivileges(const GlobalObject& global)
{
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));

  nsRefPtr<Label> privs = SANDBOX_CONFIG(compartment).GetPrivileges();

  ErrorResult aRv;
  privs = privs->Clone(aRv);

  if (aRv.Failed())
    privs = new Label(); // empty privileges

  return privs.forget();
}


// Static ====================================================================


// API exposed to Sandbox ====================================================

static JSBool
SandboxDone(JSContext *cx, unsigned argc, jsval *vp)
{
  JS::CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
    JS_ReportError(cx, "Invalid number of arguments.");
    return false;
  }

  // Structurally clone the object

  JS::RootedValue v(cx, args[0]);
  // Apply the structured clone algorithm
  StructuredCloneData data;
  JSAutoStructuredCloneBuffer buffer;

  if (!WriteStructuredClone(cx, v, buffer, data.mClosure)) {
    JS_ReportError(cx,
        "SandboxDone: Argument must be a structurally clonable object.");
    return false;
  } else {
    data.mData = buffer.data();
    data.mDataLength = buffer.nbytes();

    MOZ_ASSERT(ReadStructuredClone(cx, data, v.address())); // buffer->object
  }

  // Set the result in the sandbox

  JSCompartment* compartment = js::GetContextCompartment(cx);
  mozilla::dom::Sandbox* sandbox =
    xpc::sandbox::GetCompartmentSandbox(compartment);

  MOZ_ASSERT(sandbox); // must be in sandboxed compartment

  sandbox->SetResult(v, mozilla::dom::Sandbox::ResultType::ResultValue);

  // Handler may be called after ondone is registered, dispatch
  
  if (!sandbox->DispatchResult(cx)) {
    JS_ReportError(cx, "Failed to dispatch result.");
    return false;
  }


  return true;
}

static JSBool
SandboxOnmessage(JSContext *cx, unsigned argc, jsval *vp)
{
  // in sandbox:
  JSCompartment* compartment = js::GetContextCompartment(cx);
  mozilla::dom::Sandbox* sandbox =
    xpc::sandbox::GetCompartmentSandbox(compartment);

  MOZ_ASSERT(sandbox); // must be in sandboxed compartment

  // Raise label of sandbox
  sandbox->RaiseLabel();

  // check that the number of arguments is 1
  JS::CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
    JS_ReportError(cx, "Invalid number of arguments.");
    return false;
  }

  // make sure that the argument is a function
  JS::RootedObject callable(cx);
  if (!args[0].isObject() ||
      !JS_ValueToObject(cx, args[0], callable.address()) ||
      !JS_ObjectIsCallable(cx, callable)) {
    JS_ReportError(cx, "Argument must be a callable object.");
    return false;
  }

  // use function as an event handler
  nsRefPtr<EventHandlerNonNull> callback = new EventHandlerNonNull(callable);

  if (!callback) {
    JS_ReportError(cx, "Could not convert to handler.");
    return false;
  }

  // set the event handler
  ErrorResult aRv;
  sandbox->SetOnmessageForSandbox(callback, aRv);

  if (aRv.Failed()) {
    JS_ReportError(cx, "Could not set onmessage.");
    return false;
  }

  // Dispatch event handler
  sandbox->DispatchSandboxOnmessageEvent(aRv);
  if (aRv.Failed()) {
    JS_ReportError(cx, "Could not dispatch onmessage.");
    return false;
  }
  return true;
}

static JSBool
SandboxGetMessage(JSContext *cx, JS::HandleObject obj, JS::HandleId id,
                  JS::MutableHandleValue vp)
{
  // in sandbox:
  JSCompartment* compartment = js::GetContextCompartment(cx);
  mozilla::dom::Sandbox* sandbox =
    xpc::sandbox::GetCompartmentSandbox(compartment);

  MOZ_ASSERT(sandbox); // must be in sandboxed compartment

  // Raise label of sandbox
  sandbox->RaiseLabel();

  // Wrap and set the result
  return sandbox->SetMessageToHandle(cx, vp);
}

void
Sandbox::GetPrincipal(const GlobalObject& global, nsString& retval)
{
  retval = NS_LITERAL_STRING("");
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));

  nsIPrincipal* prin = xpc::GetCompartmentPrincipal(compartment);
  if (!prin) return;

  char *origin = NULL;
  if (NS_FAILED(prin->GetOrigin(&origin)))
    return;
  AppendASCIItoUTF16(origin, retval);
  NS_Free(origin);
}

void
Sandbox::Own(const GlobalObject& global,
             mozilla::dom::FreshPrincipal& principal)
{
  EnableSandbox(global);
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));

  MOZ_ASSERT(compartment);


  nsCOMPtr<nsIPrincipal> p = principal.Principal();
  nsRefPtr<Label> privs = SANDBOX_CONFIG(compartment).GetPrivileges();
  mozilla::ErrorResult  aRv;
  privs->_And(p, aRv);
}

// Internal ==================================================================


// Set the compartment and current sandbox labels to the sandbox
// label (set at construction time).
void
Sandbox::RaiseLabel()
{
  mCurrentPrivacy = mPrivacy;
  mCurrentTrust = mTrust;
}

// This function tries to dispatch an event. It fails silently if it
// can't dispatch an event due to the result not being set or the
// handlers not being registered.
JSBool
Sandbox::DispatchResult(JSContext* cx)
{
  // Only dispatch if result has been set
  if (mResultType == ResultNone)
    return true;

  if (!GetOnmessage() || (mResultType == ResultError && !GetOnerror()))
    return true;

  // Wrap the result
  if (!JS_WrapValue(cx, mResult.unsafeGet())) {
    ClearResult();
    return false;
  }

  nsCOMPtr<nsIDOMEvent> event;
  nsresult rv = nsEventDispatcher::CreateEvent(this, nullptr, nullptr,
                                               NS_LITERAL_STRING("Events"),
                                               getter_AddRefs(event));
  if (NS_FAILED(rv)) {
    JS_ReportError(cx, "Failed to create event.");
    return false;
  }

  event->InitEvent((mResultType == ResultError) ? NS_LITERAL_STRING("error")
                                                : NS_LITERAL_STRING("message"),
                   /* canBubble = */ false, /* canCancel = */ false);

  event->SetTrusted(true);

  DispatchDOMEvent(nullptr, event, nullptr, nullptr);

  return true;
}

void 
Sandbox::SetOnmessageForSandbox(mozilla::dom::EventHandlerNonNull* aCallback,
                                mozilla::ErrorResult& aRv)
{
  mEventTarget->SetOnmessage(aCallback, aRv);
}


void
Sandbox::Init(const GlobalObject& global, JSContext* cx, ErrorResult& aRv)
{
  nsresult rv;

  xpc::SandboxOptions options(cx);
  options.wantComponents     = false;
  options.wantXrays          = false; //FIXME
  options.wantXHRConstructor = false;

  // Set the sandbox principal and add CSP policy that restrict
  // network communication accordingly

  nsCOMPtr<nsIPrincipal> principal = mPrivacy->GetPrincipalIfSingleton();

  if (principal) {
    bool isNull;
    rv = principal->GetIsNullPrincipal(&isNull);
    if(NS_FAILED(rv)) { aRv.Throw(rv); return; }

    if (isNull) {
      //TODO: once null principals can have csp we need to change this
      //to export XHR constructor
      mPrincipal = principal;
    } else {
      // "clone" the principal
      nsCOMPtr<nsIURI> uri;
      rv = principal->GetURI(getter_AddRefs(uri));
      if(NS_FAILED(rv)) { aRv.Throw(rv); return; }

      nsCOMPtr<nsIScriptSecurityManager> secMan =
        nsContentUtils::GetSecurityManager();
      if(!secMan) { aRv.Throw(NS_ERROR_FAILURE); return; }
      rv = secMan->GetNoAppCodebasePrincipal(uri, getter_AddRefs(mPrincipal));

      if(NS_FAILED(rv)) { aRv.Throw(rv); return; }

      nsCOMPtr<nsIContentSecurityPolicy> csp =
        do_CreateInstance("@mozilla.org/contentsecuritypolicy;1", &rv);

      if(NS_FAILED(rv)) { aRv.Throw(rv); return; }

      if (csp) {
        nsString policy = NS_LITERAL_STRING("default-src 'none'; \
                                             connect-src 'self';");
        csp->RefinePolicy(policy, uri, true);
        rv = mPrincipal->SetCsp(csp);
        if(NS_FAILED(rv)) { aRv.Throw(rv); return; }
        options.wantXHRConstructor = true;
      }
    }
  } else {
    //TODO: once null principals can have csp we need to change this
    //to export XHR constructor
    mPrincipal = do_CreateInstance("@mozilla.org/nullprincipal;1", &rv);
    if(NS_FAILED(rv)) { aRv.Throw(rv); return; }
  }


  // Create sandbox object

  JS::RootedValue sandboxVal(cx, JS::UndefinedValue());

  rv = xpc_CreateSandboxObject(cx,                   //JSContext *cx, 
                               sandboxVal.address(), //jsval *vp, 
                               mPrincipal,           //nsISupports *prinOrSop, 
                               options);             //SandboxOptions& options)
  if (NS_FAILED(rv)) { 
    aRv.Throw(rv);
    return;
  }

  if (!JS_ValueToObject(cx, sandboxVal, mSandboxObj.unsafeGet()) ||
      !mSandboxObj) {
    aRv.Throw(NS_ERROR_FAILURE);
    return;
  }
  

  {
    JS::RootedObject sandboxObj(cx, js::UncheckedUnwrap(mSandboxObj));
    JSAutoRequest req(cx);
    JSAutoCompartment ac(cx, sandboxObj);
    mEventTarget = new SandboxEventTarget();

    {
      JSObject** pAI = GetProtoAndIfaceArray(sandboxObj);
      mozilla::dom::RoleBinding::CreateInterfaceObjects(cx, sandboxObj, pAI);
      mozilla::dom::LabelBinding::CreateInterfaceObjects(cx, sandboxObj, pAI);
      mozilla::dom::SandboxBinding::CreateInterfaceObjects(cx, sandboxObj, pAI);
    }
    //TODO: check if any of these fail
    JS_DefineFunction(cx, sandboxObj, "done", SandboxDone, 1, 0);
    JS_DefineFunction(cx, sandboxObj, "onmessage", SandboxOnmessage, 1, 0);
    JS_DefineProperty(cx, sandboxObj, "message", JSVAL_VOID,
                      SandboxGetMessage, NULL,
                      JSPROP_ENUMERATE | JSPROP_SHARED);
  }

  NS_HOLD_JS_OBJECTS(this, Sandbox);
}

void
Sandbox::EvalInSandbox(JSContext *cx, const nsAString& source, ErrorResult &aRv)
{
    JS_AbortIfWrongThread(JS_GetRuntime(cx));
    JSAutoRequest ar(cx);
    
    // clear the sandox funciton result
    ClearResult();

    JS::RootedObject sandbox(cx, js::UncheckedUnwrap(mSandboxObj));
    if (!sandbox) { aRv.Throw(NS_ERROR_INVALID_ARG); return; }

    nsIScriptObjectPrincipal *sop =
        (nsIScriptObjectPrincipal*)xpc_GetJSPrivate(sandbox);
    if (!sop) {
      NS_ASSERTION(sop, "Invalid sandbox passed");
      aRv.Throw(NS_ERROR_FAILURE);
      return;
    }

    nsCOMPtr<nsIPrincipal> prin = sop->GetPrincipal();
    if (!prin) { aRv.Throw(NS_ERROR_FAILURE); return; }

    // We create a separate cx to do the sandbox evaluation. Scope it.
    JS::RootedValue v(cx, JS::UndefinedValue());
    bool ok = false;
    {
        nsRefPtr<xpc::ContextHolder> sandcxHolder = 
          new xpc::ContextHolder(cx, sandbox, prin);
        JSContext *sandcx = sandcxHolder->GetJSContext();
        if (!sandcx) {
            aRv.Throw(NS_ERROR_OUT_OF_MEMORY);
            return;
        }
        nsCxPusher pusher;
        pusher.Push(sandcx);

        JSAutoRequest req(sandcx);
        JSAutoCompartment ac(sandcx, sandbox);

        JSCompartment *compartment = js::GetObjectCompartment(sandbox);
        xpc::sandbox::EnableCompartmentSandbox(compartment, this);

        JS::CompileOptions options(sandcx);
        options.setPrincipals(nsJSPrincipals::get(prin))
               .setFileAndLine("x-bogus://Sandbox", 1);
        JS::RootedObject rootedSandbox(sandcx, sandbox);
        ok = JS::Evaluate(sandcx, rootedSandbox, options,
                          PromiseFlatString(source).get(), source.Length(),
                          v.address());

        // Raise the label of the sandbox compartment to the sandbox label
        RaiseLabel();

        // If the sandbox threw an exception, grab it off the context.
        if (JS_GetPendingException(sandcx, v.address())) {
          MOZ_ASSERT(!ok);
          JS_ClearPendingException(sandcx);
        }
    }

    if (!ok)
      SetResult(v, ResultError);

    // back on caller context
    if (!DispatchResult(cx))
      aRv.Throw(NS_ERROR_FAILURE);
}
// Internal ==================================================================

// Helpers ===================================================================

// Helper for getting JSObject* from GlobalObject
JSObject*
getGlobalJSObject(const GlobalObject& global)
{
  nsCOMPtr<nsIGlobalObject> nsGlob = do_QueryInterface(global.Get());
  if (!nsGlob) {
    NS_ASSERTION(nsGlob, "QI should return global object");
    return nullptr;

  }
  return nsGlob->GetGlobalJSObject();
}

// Helper for setting the ErrorResult to a string.  This function
// should only be called after MightThrowJSException() is called.
void
JSErrorResult(JSContext *cx, ErrorResult& aRv, const char *msg)
{
  JSString *err = JS_NewStringCopyZ(cx,msg); 
  if (err) {
    JS::RootedValue errv(cx, STRING_TO_JSVAL(err));
    aRv.ThrowJSException(cx,errv);
  } else {
    aRv.Throw(NS_ERROR_OUT_OF_MEMORY);
  }
}

// Helpers ===================================================================

#undef SANDBOX_CONFIG
} // namespace dom
} // namespace mozilla
