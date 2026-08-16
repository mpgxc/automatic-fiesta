/*
 * Shim mínimo do AuthorizationPlugin.h, só para compilar e testar a lógica do
 * plugin fora do macOS. Espelha a ABI real (Security-60158.140.3) nos campos
 * que o plugin usa e na ORDEM deles — se a ordem divergir, o teste passa aqui e
 * o plugin corrompe a pilha lá, que é exatamente o erro que este arquivo não
 * pode cometer. No macOS o header de verdade é o que vale.
 */
#ifndef SHIM_AUTHORIZATIONPLUGIN_H
#define SHIM_AUTHORIZATIONPLUGIN_H

#include <stddef.h>
#include <stdint.h>

typedef int32_t  OSStatus;
typedef uint32_t UInt32;

enum { errAuthorizationSuccess = 0, errAuthorizationInternal = -60008 };

typedef enum {
    kAuthorizationResultAllow,
    kAuthorizationResultDeny,
    kAuthorizationResultUndefined,
    kAuthorizationResultUserCanceled,
} AuthorizationResult;

enum { kAuthorizationPluginInterfaceVersion = 0 };
enum { kAuthorizationCallbacksVersion = 4 };

typedef const struct AuthorizationOpaquePluginRef    *AuthorizationPluginRef;
typedef const struct AuthorizationOpaqueEngineRef    *AuthorizationEngineRef;
typedef const struct AuthorizationOpaqueMechanismRef *AuthorizationMechanismRef;
typedef const char *AuthorizationMechanismId;
typedef const char *AuthorizationString;

typedef struct { UInt32 length; void *data; } AuthorizationValue;
typedef UInt32 AuthorizationContextFlags;

typedef struct {
    UInt32 version;
    OSStatus (*SetResult)(AuthorizationEngineRef, AuthorizationResult);
    OSStatus (*RequestInterrupt)(AuthorizationEngineRef);
    OSStatus (*DidDeactivate)(AuthorizationEngineRef);
    OSStatus (*GetContextValue)(AuthorizationEngineRef, AuthorizationString,
                                AuthorizationContextFlags *, const AuthorizationValue **);
    OSStatus (*SetContextValue)(AuthorizationEngineRef, AuthorizationString,
                                AuthorizationContextFlags, const AuthorizationValue *);
    OSStatus (*GetHintValue)(AuthorizationEngineRef, AuthorizationString,
                             const AuthorizationValue **);
    OSStatus (*SetHintValue)(AuthorizationEngineRef, AuthorizationString,
                             const AuthorizationValue *);
} AuthorizationCallbacks;

typedef struct {
    UInt32 version;
    OSStatus (*PluginDestroy)(AuthorizationPluginRef);
    OSStatus (*MechanismCreate)(AuthorizationPluginRef, AuthorizationEngineRef,
                                AuthorizationMechanismId, AuthorizationMechanismRef *);
    OSStatus (*MechanismInvoke)(AuthorizationMechanismRef);
    OSStatus (*MechanismDeactivate)(AuthorizationMechanismRef);
    OSStatus (*MechanismDestroy)(AuthorizationMechanismRef);
} AuthorizationPluginInterface;

OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *,
                                   AuthorizationPluginRef *,
                                   const AuthorizationPluginInterface **);
#endif
