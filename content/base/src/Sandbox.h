/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "mozilla/Attributes.h"
#include "mozilla/ErrorResult.h"
#include "mozilla/dom/Label.h"
#include "mozilla/dom/FreshPrincipal.h"
#include "mozilla/dom/SandboxBinding.h"
#include "nsCycleCollectionParticipant.h"
#include "nsWrapperCache.h"
#include "nsCOMPtr.h"
#include "nsString.h"
#include "nsIDocument.h"
#include "nsDOMEventTargetHelper.h"

struct JSContext;

namespace xpc {
namespace sandbox {
  class SandboxConfig;
};
};

namespace mozilla {
namespace dom {

class SandboxEventTarget MOZ_FINAL : public nsDOMEventTargetHelper
{
public:
  NS_DECL_ISUPPORTS_INHERITED
  NS_DECL_CYCLE_COLLECTION_SCRIPT_HOLDER_CLASS_INHERITED(SandboxEventTarget,
                                                         nsDOMEventTargetHelper)

  SandboxEventTarget()
  {
    SetIsDOMBinding();
  }

  ~SandboxEventTarget() { }

  nsISupports* GetParentObject() const
  {
    return GetOwner();
  }

  JSObject* WrapObject(JSContext* aCx, JS::Handle<JSObject*> aScope) MOZ_OVERRIDE
  {
    return SandboxEventTargetBinding::Wrap(aCx, aScope, this);
  }

  IMPL_EVENT_HANDLER(message)
};

class Sandbox MOZ_FINAL : public nsDOMEventTargetHelper
{
public: // New types =========================================================
  enum ResultType { ResultNone, ResultValue, ResultError };

public: // DOM interface =====================================================
  NS_DECL_ISUPPORTS_INHERITED
  NS_DECL_CYCLE_COLLECTION_SCRIPT_HOLDER_CLASS_INHERITED(Sandbox,
                                                         nsDOMEventTargetHelper)

  Sandbox();
  Sandbox(mozilla::dom::Label& privacy);
  Sandbox(mozilla::dom::Label& privacy, mozilla::dom::Label& trust);

  ~Sandbox();
  void Destroy();

  nsISupports* GetParentObject() const
  {
    return GetOwner();
  }

  JSObject* WrapObject(JSContext* aCx, 
                       JS::Handle<JSObject*> aScope) MOZ_OVERRIDE
  {
    return SandboxBinding::Wrap(aCx, aScope, this);
  }

  static already_AddRefed<Sandbox> Constructor(const GlobalObject& global, 
                                               JSContext* cx, ErrorResult& aRv);
  static already_AddRefed<Sandbox> Constructor(const GlobalObject& global,
                                               JSContext* cx, 
                                               mozilla::dom::Label& privacy, 
                                               ErrorResult& aRv);
  static already_AddRefed<Sandbox> Constructor(const GlobalObject& global, 
                                               JSContext* cx, 
                                               mozilla::dom::Label& privacy, 
                                               mozilla::dom::Label& trust, 
                                               ErrorResult& aRv);

  void Schedule(JSContext* cx, const nsAString& src, ErrorResult& aRv);
  void ScheduleURI(JSContext* cx, const nsAString& aURL, ErrorResult& aRv);

  already_AddRefed<Label> Privacy() const;
  already_AddRefed<Label> Trust() const;

  bool IsClean() const;

  void Ondone(JSContext* cx, EventHandlerNonNull* successHandler, 
              const Optional<nsRefPtr<EventHandlerNonNull> >& errorHandler,
              ErrorResult& aRv);

  void PostMessage(JSContext* cx, JS::Handle<JS::Value> message, 
                   ErrorResult& aRv);

  IMPL_EVENT_HANDLER(message)
  IMPL_EVENT_HANDLER(error)

  JS::Value Result(JSContext* cx);


  // result from sandbox related
  JS::Value GetResult(JSContext* cx, ErrorResult& aRv) const {
    return reinterpret_cast<const Sandbox*>(this)->GetResult(cx,aRv);
  }
  JS::Value GetResult(JSContext* cx, ErrorResult& aRv);

  void Grant(JSContext* cx, mozilla::dom::FreshPrincipal& principal);
public: 
  // C++ only
  // FIXME: these should not really be public
  inline void SetResult(JS::Handle<JS::Value> val, ResultType type);
  inline void ClearResult();

  // message to sandbox related
  inline void SetMessage(JS::Handle<JS::Value> val);
  inline void ClearMessage();
  bool SetMessageToHandle(JSContext *cx, JS::MutableHandleValue vp);


public: // Static DOM interface ==============================================

  static void EnableSandbox(const GlobalObject& global);
  static bool IsSandboxed(const GlobalObject& global);
  static bool IsSandbox(const GlobalObject& global);
  static bool IsSandboxMode(const GlobalObject& global);

  // label

  static void SetPrivacyLabel(const GlobalObject& global, JSContext* cx,
                              mozilla::dom::Label& aLabel, ErrorResult& aRv);
  static already_AddRefed<Label> GetPrivacyLabel(const GlobalObject& global,
                                                 JSContext* cx);

  static void SetTrustLabel(const GlobalObject& global, JSContext* cx,
                            mozilla::dom::Label& aLabel, ErrorResult& aRv);
  static already_AddRefed<Label> GetTrustLabel(const GlobalObject& global,
                                               JSContext* cx);

  // clearance

  static void SetPrivacyClearance(const GlobalObject& global, JSContext* cx,
                                  mozilla::dom::Label& aLabel,
                                  ErrorResult& aRv);
  static already_AddRefed<Label> GetPrivacyClearance(const GlobalObject& global,
                                                     JSContext* cx);

  static void SetTrustClearance(const GlobalObject& global, JSContext* cx,
                                mozilla::dom::Label& aLabel, ErrorResult& aRv);
  static already_AddRefed<Label> GetTrustClearance(const GlobalObject& global,
                                                   JSContext* cx);

  // privs

  // Get underlying pricipal
  static void GetPrincipal(const GlobalObject& global, nsString& retval); 

  // Ownership
  static already_AddRefed<Label> GetPrivileges(const GlobalObject& global);

  // Take ownership of principal
  static void Own(const GlobalObject& global,
                  mozilla::dom::FreshPrincipal& principal);


  //misc

  // Import script from specified url
  static JS::Value Import(const GlobalObject& global, JSContext* cx,
                          const nsAString& aURL, ErrorResult& aRv);

public: // TODO REMOVE =======================================================
  JSObject* GetSandbox(JSContext* cx) const { return mSandboxObj; }

public: // Internal ==========================================================

  // Raise sandbox and compartment labels
  void RaiseLabel();

  // Call onmessage handler registered _on_ the sandbox
  JSBool DispatchResult(JSContext* cx);

  // Set onmessage property _in_ the sandbox, this is called when the
  // owner posts a message _to_ the sandbox
  void SetOnmessageForSandbox(mozilla::dom::EventHandlerNonNull* aCallback,
                              mozilla::ErrorResult& aRv);
  // Dispatch the onmessage event _in_ the sandbox
  void DispatchSandboxOnmessageEvent(ErrorResult& aRv);

protected: // Unsafe functions ===============================================
  // These functions are part of the trusted computing base and should
  // not be exposed to untrusted code
  already_AddRefed<Label> CurrentPrivacy() const;
  already_AddRefed<Label> CurrentTrust() const;
  void SetCurrentPrivacy(mozilla::dom::Label* aLabel);
  void SetCurrentTrust(mozilla::dom::Label* aLabel);

  friend class xpc::sandbox::SandboxConfig;

private:

  void Init(const GlobalObject& global, JSContext* cx, ErrorResult& aRv);
  void EvalInSandbox(JSContext *cx, const nsAString& source, ErrorResult &aRv);


  // What is the sandbox Label?
  nsRefPtr<Label> mPrivacy;
  nsRefPtr<Label> mTrust;

  // What is the sandbox current label
  nsRefPtr<Label> mCurrentPrivacy;
  nsRefPtr<Label> mCurrentTrust;

  // What is the underlying sandbox principal
  nsCOMPtr<nsIPrincipal> mPrincipal;

  // Underlying sandbox object
  JS::Heap<JSObject*> mSandboxObj;

  // Sandbox computation result
  JS::Heap<JS::Value> mResult;
  ResultType mResultType;

  // Sandbox event target
  nsRefPtr<SandboxEventTarget> mEventTarget;
  // Message to sandbox
  JS::Heap<JS::Value> mMessage;
  bool mMessageIsSet;
};

} // namespace dom
} // namespace mozilla
