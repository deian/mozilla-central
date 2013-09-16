/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/dom/FreshPrincipal.h"
#include "mozilla/dom/Sandbox.h"
#include "mozilla/dom/FreshPrincipalBinding.h"
#include "nsContentUtils.h"
#include "nsCOMPtr.h"
#include "nsComponentManagerUtils.h"

namespace mozilla {
namespace dom {


NS_IMPL_CYCLE_COLLECTION_WRAPPERCACHE_1(FreshPrincipal, mPrincipal)
NS_IMPL_CYCLE_COLLECTING_ADDREF(FreshPrincipal)
NS_IMPL_CYCLE_COLLECTING_RELEASE(FreshPrincipal)
NS_INTERFACE_MAP_BEGIN_CYCLE_COLLECTION(FreshPrincipal)
  NS_WRAPPERCACHE_INTERFACE_MAP_ENTRY
  NS_INTERFACE_MAP_ENTRY(nsISupports)
NS_INTERFACE_MAP_END

FreshPrincipal::FreshPrincipal()
  : mPrincipal(do_CreateInstance("@mozilla.org/nullprincipal;1"))
{
  SetIsDOMBinding();
  MOZ_ASSERT(mPrincipal);
}

FreshPrincipal::FreshPrincipal(nsresult &rv)
  : mPrincipal(do_CreateInstance("@mozilla.org/nullprincipal;1", &rv))
{
  SetIsDOMBinding();
}

FreshPrincipal::~FreshPrincipal()
{
}

FreshPrincipal*
FreshPrincipal::GetParentObject() const
{
  return nullptr; //TODO: return something sensible here
}

JSObject*
FreshPrincipal::WrapObject(JSContext* aCx, JS::Handle<JSObject*> aScope)
{
  return FreshPrincipalBinding::Wrap(aCx, aScope, this);
}

already_AddRefed<FreshPrincipal>
FreshPrincipal::Constructor(const GlobalObject& global, 
                            JSContext *cx, ErrorResult& aRv)
{
  nsresult rv;
  nsRefPtr<FreshPrincipal> p = new FreshPrincipal(rv);
  if (NS_SUCCEEDED(rv)) {
    Sandbox::Own(global, cx, *p);
    return p.forget();
  }

  aRv.Throw(rv);
  return nullptr;
}

already_AddRefed<nsIPrincipal>
FreshPrincipal::Principal() const
{
  nsCOMPtr<nsIPrincipal> p = mPrincipal;
  return p.forget();
}

void
FreshPrincipal::Stringify(nsString& retval)
{
  char *origin = NULL;
  nsresult rv = mPrincipal->GetOrigin(&origin);
  if (NS_FAILED(rv) || !origin) {
    retval = NS_LITERAL_STRING("x-bogus:<unknown-principal>");
  } else {
    retval.Truncate();
    AppendASCIItoUTF16(origin, retval);
    NS_Free(origin);
  }
}

} // namespace dom
} // namespace mozilla
