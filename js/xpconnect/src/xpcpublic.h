/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 * vim: set ts=8 sw=4 et tw=78:
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef xpcpublic_h
#define xpcpublic_h

#include "jsapi.h"
#include "jsproxy.h"
#include "js/HeapAPI.h"
#include "js/GCAPI.h"

#include "nsISupports.h"
#include "nsIURI.h"
#include "nsIPrincipal.h"
#include "nsWrapperCache.h"
#include "nsStringGlue.h"
#include "nsTArray.h"
#include "mozilla/dom/JSSlots.h"
#include "nsMathUtils.h"
#include "nsStringBuffer.h"
#include "nsIGlobalObject.h"
#include "mozilla/dom/BindingDeclarations.h"

class nsIPrincipal;
class nsIXPConnectWrappedJS;
class nsScriptNameSpaceManager;
class nsIGlobalObject;

#ifndef BAD_TLS_INDEX
#define BAD_TLS_INDEX ((uint32_t) -1)
#endif

namespace xpc {
JSObject *
TransplantObject(JSContext *cx, JS::HandleObject origobj, JS::HandleObject target);

JSObject *
TransplantObjectWithWrapper(JSContext *cx,
                            JS::HandleObject origobj, JS::HandleObject origwrapper,
                            JS::HandleObject targetobj, JS::HandleObject targetwrapper);

// Return a raw XBL scope object corresponding to contentScope, which must
// be an object whose global is a DOM window.
//
// The return value is not wrapped into cx->compartment, so be sure to enter
// its compartment before doing anything meaningful.
//
// Also note that XBL scopes are lazily created, so the return-value should be
// null-checked unless the caller can ensure that the scope must already
// exist.
JSObject *
GetXBLScope(JSContext *cx, JSObject *contentScope);

// Returns whether XBL scopes have been explicitly disabled for code running
// in this compartment. See the comment around mAllowXBLScope.
bool
AllowXBLScope(JSCompartment *c);

bool
IsSandboxPrototypeProxy(JSObject *obj);

bool
IsReflector(JSObject *obj);
} /* namespace xpc */

namespace JS {

struct RuntimeStats;

}

#define XPCONNECT_GLOBAL_FLAGS_WITH_EXTRA_SLOTS(n)                            \
    JSCLASS_DOM_GLOBAL | JSCLASS_HAS_PRIVATE |                                \
    JSCLASS_PRIVATE_IS_NSISUPPORTS | JSCLASS_IMPLEMENTS_BARRIERS |            \
    JSCLASS_GLOBAL_FLAGS_WITH_SLOTS(DOM_GLOBAL_SLOTS + n)

#define XPCONNECT_GLOBAL_EXTRA_SLOT_OFFSET (JSCLASS_GLOBAL_SLOT_COUNT + DOM_GLOBAL_SLOTS)

#define XPCONNECT_GLOBAL_FLAGS XPCONNECT_GLOBAL_FLAGS_WITH_EXTRA_SLOTS(0)

void
TraceXPCGlobal(JSTracer *trc, JSObject *obj);

// XXX These should be moved into XPCJSRuntime!
NS_EXPORT_(bool)
xpc_LocalizeRuntime(JSRuntime *rt);
NS_EXPORT_(void)
xpc_DelocalizeRuntime(JSRuntime *rt);

// If IS_WN_CLASS for the JSClass of an object is true, the object is a
// wrappednative wrapper, holding the XPCWrappedNative in its private slot.

static inline bool IS_WN_CLASS(const js::Class* clazz)
{
    return clazz->ext.isWrappedNative;
}
static inline bool IS_WN_REFLECTOR(JSObject *obj)
{
    return IS_WN_CLASS(js::GetObjectClass(obj));
}

extern bool
xpc_OkToHandOutWrapper(nsWrapperCache *cache);

inline JSObject*
xpc_FastGetCachedWrapper(nsWrapperCache *cache, JSObject *scope, jsval *vp)
{
    if (cache) {
        JSObject* wrapper = cache->GetWrapper();
        if (wrapper &&
            js::GetObjectCompartment(wrapper) == js::GetObjectCompartment(scope) &&
            (cache->IsDOMBinding() ? !cache->HasSystemOnlyWrapper() :
                                     xpc_OkToHandOutWrapper(cache))) {
            *vp = OBJECT_TO_JSVAL(wrapper);
            return wrapper;
        }
    }

    return nullptr;
}

// The JS GC marks objects gray that are held alive directly or
// indirectly by an XPConnect root. The cycle collector explores only
// this subset of the JS heap.
inline bool
xpc_IsGrayGCThing(void *thing)
{
    return JS::GCThingIsMarkedGray(thing);
}

// The cycle collector only cares about some kinds of GCthings that are
// reachable from an XPConnect root. Implemented in nsXPConnect.cpp.
extern bool
xpc_GCThingIsGrayCCThing(void *thing);

inline JSScript *
xpc_UnmarkGrayScript(JSScript *script)
{
    if (script)
        JS::ExposeGCThingToActiveJS(script, JSTRACE_SCRIPT);

    return script;
}

// If aVariant is an XPCVariant, this marks the object to be in aGeneration.
// This also unmarks the gray JSObject.
extern void
xpc_MarkInCCGeneration(nsISupports* aVariant, uint32_t aGeneration);

// If aWrappedJS is a JS wrapper, unmark its JSObject.
extern void
xpc_TryUnmarkWrappedGrayObject(nsISupports* aWrappedJS);

extern void
xpc_UnmarkSkippableJSHolders();

// No JS can be on the stack when this is called. Probably only useful from
// xpcshell.
NS_EXPORT_(void)
xpc_ActivateDebugMode();

class nsIMemoryReporterCallback;

// readable string conversions, static methods and members only
class XPCStringConvert
{
public:

    // If the string shares the readable's buffer, that buffer will
    // get assigned to *sharedBuffer.  Otherwise null will be
    // assigned.
    static jsval ReadableToJSVal(JSContext *cx, const nsAString &readable,
                                 nsStringBuffer** sharedBuffer);

    // Convert the given stringbuffer/length pair to a jsval
    static MOZ_ALWAYS_INLINE bool
    StringBufferToJSVal(JSContext* cx, nsStringBuffer* buf, uint32_t length,
                        JS::Value* rval, bool* sharedBuffer)
    {
        if (buf == sCachedBuffer &&
            JS::GetGCThingZone(sCachedString) == js::GetContextZone(cx))
        {
            *rval = JS::StringValue(sCachedString);
            *sharedBuffer = false;
            return true;
        }

        JSString *str = JS_NewExternalString(cx,
                                             static_cast<jschar*>(buf->Data()),
                                             length, &sDOMStringFinalizer);
        if (!str) {
            return false;
        }
        *rval = JS::StringValue(str);
        sCachedString = str;
        sCachedBuffer = buf;
        *sharedBuffer = true;
        return true;
    }

    static void ClearCache();

private:
    static nsStringBuffer* sCachedBuffer;
    static JSString* sCachedString;
    static const JSStringFinalizer sDOMStringFinalizer;

    static void FinalizeDOMString(const JSStringFinalizer *fin, jschar *chars);

    XPCStringConvert();         // not implemented
};

namespace xpc {

// If these functions return false, then an exception will be set on cx.
NS_EXPORT_(bool) Base64Encode(JSContext *cx, JS::Value val, JS::Value *out);
NS_EXPORT_(bool) Base64Decode(JSContext *cx, JS::Value val, JS::Value *out);

/**
 * Convert an nsString to jsval, returning true on success.
 * Note, the ownership of the string buffer may be moved from str to rval.
 * If that happens, str will point to an empty string after this call.
 */
bool NonVoidStringToJsval(JSContext *cx, nsAString &str, JS::Value *rval);
inline bool StringToJsval(JSContext *cx, nsAString &str, JS::Value *rval)
{
    // From the T_DOMSTRING case in XPCConvert::NativeData2JS.
    if (str.IsVoid()) {
        *rval = JSVAL_NULL;
        return true;
    }
    return NonVoidStringToJsval(cx, str, rval);
}

inline bool
NonVoidStringToJsval(JSContext* cx, const nsAString& str, JS::Value *rval)
{
    nsString mutableCopy(str);
    return NonVoidStringToJsval(cx, mutableCopy, rval);
}

inline bool
StringToJsval(JSContext* cx, const nsAString& str, JS::Value *rval)
{
    nsString mutableCopy(str);
    return StringToJsval(cx, mutableCopy, rval);
}

/**
 * As above, but for mozilla::dom::DOMString.
 */
MOZ_ALWAYS_INLINE
bool NonVoidStringToJsval(JSContext* cx, mozilla::dom::DOMString& str,
                          JS::Value *rval)
{
    if (!str.HasStringBuffer()) {
        // It's an actual XPCOM string
        return NonVoidStringToJsval(cx, str.AsAString(), rval);
    }

    uint32_t length = str.StringBufferLength();
    if (length == 0) {
        *rval = JS_GetEmptyStringValue(cx);
        return true;
    }

    nsStringBuffer* buf = str.StringBuffer();
    bool shared;
    if (!XPCStringConvert::StringBufferToJSVal(cx, buf, length, rval,
                                               &shared)) {
        return false;
    }
    if (shared) {
        // JS now needs to hold a reference to the buffer
        buf->AddRef();
    }
    return true;
}

MOZ_ALWAYS_INLINE
bool StringToJsval(JSContext* cx, mozilla::dom::DOMString& str,
                   JS::Value *rval)
{
    if (str.IsNull()) {
        *rval = JS::NullValue();
        return true;
    }
    return NonVoidStringToJsval(cx, str, rval);
}

nsIPrincipal *GetCompartmentPrincipal(JSCompartment *compartment);
nsIPrincipal *GetObjectPrincipal(JSObject *obj);

bool IsXBLScope(JSCompartment *compartment);

void SetLocationForGlobal(JSObject *global, const nsACString& location);
void SetLocationForGlobal(JSObject *global, nsIURI *locationURI);

/**
 * Define quick stubs on the given object, @a proto.
 *
 * @param cx
 *     A context.  Requires request.
 * @param proto
 *     The (newly created) prototype object for a DOM class.  The JS half
 *     of an XPCWrappedNativeProto.
 * @param flags
 *     Property flags for the quick stub properties--should be either
 *     JSPROP_ENUMERATE or 0.
 * @param interfaceCount
 *     The number of interfaces the class implements.
 * @param interfaceArray
 *     The interfaces the class implements; interfaceArray and
 *     interfaceCount are like what nsIClassInfo.getInterfaces returns.
 */
bool
DOM_DefineQuickStubs(JSContext *cx, JSObject *proto, uint32_t flags,
                     uint32_t interfaceCount, const nsIID **interfaceArray);


// ReportJSRuntimeExplicitTreeStats will expect this in the |extra| member
// of JS::ZoneStats.
class ZoneStatsExtras {
public:
    ZoneStatsExtras()
    {}

    nsAutoCString pathPrefix;

private:
    ZoneStatsExtras(const ZoneStatsExtras &other) MOZ_DELETE;
    ZoneStatsExtras& operator=(const ZoneStatsExtras &other) MOZ_DELETE;
};

// ReportJSRuntimeExplicitTreeStats will expect this in the |extra| member
// of JS::CompartmentStats.
class CompartmentStatsExtras {
public:
    CompartmentStatsExtras()
    {}

    nsAutoCString jsPathPrefix;
    nsAutoCString domPathPrefix;
    nsCOMPtr<nsIURI> location;

private:
    CompartmentStatsExtras(const CompartmentStatsExtras &other) MOZ_DELETE;
    CompartmentStatsExtras& operator=(const CompartmentStatsExtras &other) MOZ_DELETE;
};

// This reports all the stats in |rtStats| that belong in the "explicit" tree,
// (which isn't all of them).
// @see ZoneStatsExtras
// @see CompartmentStatsExtras
nsresult
ReportJSRuntimeExplicitTreeStats(const JS::RuntimeStats &rtStats,
                                 const nsACString &rtPath,
                                 nsIMemoryReporterCallback *cb,
                                 nsISupports *closure, size_t *rtTotal = NULL);

/**
 * Throws an exception on cx and returns false.
 */
bool
Throw(JSContext *cx, nsresult rv);

/**
 * Every global should hold a native that implements the nsIGlobalObject interface.
 */
nsIGlobalObject *
GetNativeForGlobal(JSObject *global);

/**
 * In some cases a native object does not really belong to any compartment (XBL,
 * document created from by XHR of a worker, etc.). But when for some reason we
 * have to wrap these natives (because of an event for example) instead of just
 * wrapping them into some random compartment we find on the context stack (like
 * we did previously) a default compartment is used. This function returns that
 * compartment's global. It is a singleton on the runtime.
 * If you find yourself wanting to use this compartment, you're probably doing
 * something wrong. Callers MUST consult with the XPConnect module owner before
 * using this compartment. If you don't, bholley will hunt you down.
 */
JSObject *
GetJunkScope();

/**
 * Returns the native global of the junk scope. See comment of GetJunkScope
 * about the conditions of using it.
 */
nsIGlobalObject *
GetJunkScopeGlobal();

// Error reporter used when there is no associated DOM window on to which to
// report errors and warnings.
void
SystemErrorReporter(JSContext *cx, const char *message, JSErrorReport *rep);

class Label;
class Sandbox;

// We have a separate version that's exported with external linkage for use by
// xpcshell, since external linkage on windows changes the signature to make it
// incompatible with the JSErrorReporter type, causing JS_SetErrorReporter calls
// to fail to compile.
NS_EXPORT_(void)
SystemErrorReporterExternal(JSContext *cx, const char *message,
                            JSErrorReport *rep);

NS_EXPORT_(void)
SimulateActivityCallback(bool aActive);

} // namespace xpc

namespace mozilla {
namespace dom {

typedef JSObject*
(*DefineInterface)(JSContext *cx, JS::Handle<JSObject*> global,
                   JS::Handle<jsid> id, bool defineOnGlobal);

typedef JSObject*
(*ConstructNavigatorProperty)(JSContext *cx, JS::Handle<JSObject*> naviObj);

// Check whether a constructor should be enabled for the given object.
// Note that the object should NOT be an Xray, since Xrays will end up
// defining constructors on the underlying object.
// This is a typedef for the function type itself, not the function
// pointer, so it's more obvious that pointers to a ConstructorEnabled
// can be null.
typedef bool
(ConstructorEnabled)(JSContext* cx, JS::Handle<JSObject*> obj);

extern bool
DefineStaticJSVals(JSContext *cx);
void
Register(nsScriptNameSpaceManager* aNameSpaceManager);

/**
 * A test for whether WebIDL methods that should only be visible to
 * chrome or XBL scopes should be exposed.
 */
bool IsChromeOrXBL(JSContext* cx, JSObject* /* unused */);

} // namespace dom
} // namespace mozilla

// Sandbox related
namespace xpc {
namespace sandbox {

// Turn compartment into a Sandboxed compartment. If a sandbox is provided the
// compartment sandbox is set; otherwise sandbox-mode is enabled with the
// compartment label iset to the public label.
NS_EXPORT_(void)
EnableCompartmentSandbox(JSCompartment *compartment,
                         mozilla::dom::Sandbox *sandbox = nullptr);

// Is the compartment a sandbox or in sandbox-mode
NS_EXPORT_(bool)
IsCompartmentSandboxed(JSCompartment *compartment);

NS_EXPORT_(bool)
IsCompartmentSandbox(JSCompartment *compartment);

NS_EXPORT_(bool)
IsCompartmentSandboxMode(JSCompartment *compartment);

NS_EXPORT_(void)
FreezeCompartmentSandbox(JSCompartment *compartment);

NS_EXPORT_(bool)
IsCompartmentSandboxFrozen(JSCompartment *compartment);

#define DECLARE_SET_LABEL(name)                       \
    NS_EXPORT_(void)                                  \
    SetCompartment##name(JSCompartment *compartment,  \
                         mozilla::dom::Label *aLabel);

#define DECLARE_GET_LABEL(name)                       \
    NS_EXPORT_(already_AddRefed<mozilla::dom::Label>) \
    GetCompartment##name(JSCompartment *compartment);

// Compartment label
DECLARE_SET_LABEL(PrivacyLabel);
DECLARE_GET_LABEL(PrivacyLabel);

DECLARE_SET_LABEL(TrustLabel);
DECLARE_GET_LABEL(TrustLabel);

// Compartment clearance
DECLARE_SET_LABEL(PrivacyClearance);
DECLARE_GET_LABEL(PrivacyClearance);

DECLARE_SET_LABEL(TrustClearance);
DECLARE_GET_LABEL(TrustClearance);

DECLARE_SET_LABEL(Privileges);
DECLARE_GET_LABEL(Privileges);

#undef DECLARE_SET_LABEL
#undef DECLARE_GET_LABEL

// If the compartment is a sandbox, return the associated sandbox. If the
// compartment is in sandbox-mode, return nullptr.
NS_EXPORT_(mozilla::dom::Sandbox*)
GetCompartmentSandbox(JSCompartment *compartment);


// Can information flow form source to compartment
NS_EXPORT_(bool)
GuardRead(JSCompartment *compartment, JSCompartment *source, bool isRead = true);

// Can information flow to compartment from object labeld with privacy and trust
NS_EXPORT_(bool)
GuardRead(JSCompartment *compatment,
          mozilla::dom::Label &privacy, mozilla::dom::Label &trust,
          mozilla::dom::Label *aPrivs = nullptr);

} // namespace sandbox
} // namespace xpc

#endif
