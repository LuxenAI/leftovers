#include <Security/CSCommon.h>
#include <Security/SecCode.h>
#include <Security/SecStaticCode.h>

/*
 * Pin every numeric SecCSFlags value used by NativeBrokerTrustAdapter.swift to
 * the official SDK declarations.  Compilation must fail if an SDK changes any
 * declaration instead of silently retaining stale Swift literals.
 */
_Static_assert(kSecCSDefaultFlags == 0, "kSecCSDefaultFlags changed");
_Static_assert(kSecCSCheckAllArchitectures == (1u << 0),
               "kSecCSCheckAllArchitectures changed");
_Static_assert(kSecCSStrictValidate == (1u << 4), "kSecCSStrictValidate changed");
_Static_assert(kSecCSNoNetworkAccess == (1u << 29), "kSecCSNoNetworkAccess changed");
_Static_assert(kSecCSSigningInformation == (1u << 1),
               "kSecCSSigningInformation changed");
_Static_assert(kSecCSRequirementInformation == (1u << 2),
               "kSecCSRequirementInformation changed");
