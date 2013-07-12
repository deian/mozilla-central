/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "mozilla/Attributes.h"
#include "mozilla/ErrorResult.h"
#include "nsCycleCollectionParticipant.h"
#include "nsWrapperCache.h"
#include "nsIDocument.h"
#include "nsCOMPtr.h"
#include "nsContentUtils.h"

struct JSContext;

namespace mozilla {
namespace dom {

class FreshPrincipal MOZ_FINAL : public nsISupports
                               , public nsWrapperCache
{
public:
  NS_DECL_CYCLE_COLLECTING_ISUPPORTS
  NS_DECL_CYCLE_COLLECTION_SCRIPT_HOLDER_CLASS(FreshPrincipal)

public:
  FreshPrincipal();
  FreshPrincipal(nsresult &rv);

  ~FreshPrincipal();

  FreshPrincipal* GetParentObject() const; //FIXME

  virtual JSObject* WrapObject(JSContext* aCx, 
                               JS::Handle<JSObject*> aScope) MOZ_OVERRIDE;

  static already_AddRefed<FreshPrincipal>
    Constructor(const GlobalObject& global, ErrorResult& aRv);

  already_AddRefed<nsIPrincipal> Principal() const;

  void Stringify(nsString& retval);

private:
  nsCOMPtr<nsIPrincipal> mPrincipal;
};

} // namespace dom
} // namespace mozilla
