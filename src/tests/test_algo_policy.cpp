/*
* Algorithm Policy Tests
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/algo_policy.h>
#include <botan/exceptn.h>

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   #include <botan/block_cipher.h>
#endif

#if defined(BOTAN_HAS_CIPHER_MODES)
   #include <botan/cipher_mode.h>
#endif

#if defined(BOTAN_HAS_HASH)
   #include <botan/hash.h>
#endif

#if defined(BOTAN_HAS_MAC)
   #include <botan/mac.h>
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
   #include <botan/stream_cipher.h>
#endif

namespace Botan_Tests {

namespace {

/*
* Installs a policy for the duration of a test and restores the default
* (standard) policy afterwards, so other tests are not affected.
*/
class Scoped_Algorithm_Policy final {
   public:
      explicit Scoped_Algorithm_Policy(const Botan::Algorithm_Policy& policy) { Botan::set_algorithm_policy(policy); }

      ~Scoped_Algorithm_Policy() { Botan::set_algorithm_policy(Botan::Algorithm_Policy::standard()); }

      Scoped_Algorithm_Policy(const Scoped_Algorithm_Policy&) = delete;
      Scoped_Algorithm_Policy& operator=(const Scoped_Algorithm_Policy&) = delete;
};

Test::Result test_default_policy() {
   Test::Result result("default algorithm policy");

   result.test_str_eq("default policy is 'standard'", Botan::algorithm_policy().policy_name(), "standard");

   // The standard policy permits every algorithm, preserving historical behavior
   result.test_is_true("standard policy permits MD5", Botan::algorithm_permitted("MD5"));
   result.test_is_true("standard policy permits Blowfish", Botan::algorithm_permitted("Blowfish"));
   result.test_is_true("standard policy permits RC4", Botan::algorithm_permitted("RC4"));
   result.test_is_true("standard policy permits composed specs", Botan::algorithm_permitted("AES-256/CBC/PKCS7"));
   result.test_is_true("standard policy permits nested specs", Botan::algorithm_permitted("HMAC(MD5)"));

#if defined(BOTAN_HAS_HASH) && defined(BOTAN_HAS_MD5)
   // The existing factory API behaves as before when no policy was installed
   result.test_not_null("MD5 can be created under the default policy", Botan::HashFunction::create_or_throw("MD5"));
   result.test_is_true("MD5 precheck is available", Botan::algorithm_available<Botan::HashFunction>("MD5"));
#endif

   return result;
}

Test::Result test_fips_policy() {
   Test::Result result("FIPS 140-3 algorithm policy");

   const Scoped_Algorithm_Policy policy(Botan::Algorithm_Policy::fips_140());

   result.test_str_eq("active policy is FIPS", Botan::algorithm_policy().policy_name(), "FIPS 140-3");

   // Availability precheck
   result.test_is_true("FIPS permits AES-256", Botan::algorithm_permitted("AES-256"));
   result.test_is_true("FIPS permits SHA-256", Botan::algorithm_permitted("SHA-256"));
   result.test_is_true("FIPS permits HMAC(SHA-256)", Botan::algorithm_permitted("HMAC(SHA-256)"));
   result.test_is_true("FIPS permits AES-256/GCM", Botan::algorithm_permitted("AES-256/GCM"));
   result.test_is_false("FIPS rejects Blowfish", Botan::algorithm_permitted("Blowfish"));
   result.test_is_false("FIPS rejects MD5", Botan::algorithm_permitted("MD5"));
   result.test_is_false("FIPS rejects SHA-1", Botan::algorithm_permitted("SHA-1"));
   result.test_is_false("FIPS rejects RC4", Botan::algorithm_permitted("RC4"));
   result.test_is_false("FIPS rejects ChaCha20", Botan::algorithm_permitted("ChaCha20"));
   result.test_is_false("FIPS rejects HMAC(MD5)", Botan::algorithm_permitted("HMAC(MD5)"));
   result.test_is_false("FIPS rejects AES-256/EAX", Botan::algorithm_permitted("AES-256/EAX"));

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   // A non-approved algorithm is rejected at initialization, with a clear reason
   try {
      Botan::BlockCipher::create_or_throw("Blowfish");
      result.test_failure("Blowfish was not rejected by the FIPS policy");
   } catch(const Botan::Algorithm_Not_Permitted& e) {
      result.test_str_contains("rejection names the algorithm", e.what(), "Blowfish");
      result.test_str_contains("rejection names the policy", e.what(), "FIPS 140-3");
      result.test_str_contains("rejection explains the reason", e.what(), "not in the approved algorithm whitelist");
      result.test_enum_eq("error type", e.error_type(), Botan::ErrorType::AlgorithmNotPermitted);
   }

   result.test_str_eq("error type name",
                      Botan::to_string(Botan::ErrorType::AlgorithmNotPermitted),
                      "AlgorithmNotPermitted");

   // The non-throwing factory signals rejection by returning nullptr
   result.test_is_true("create() returns nullptr for a rejected algorithm",
                       Botan::BlockCipher::create("Blowfish") == nullptr);

   // Precheck combining policy and compiled-in availability
   result.test_is_false("Blowfish is not available under FIPS",
                        Botan::algorithm_available<Botan::BlockCipher>("Blowfish"));

   #if defined(BOTAN_HAS_AES)
   result.test_is_true("AES-256 is available under FIPS", Botan::algorithm_available<Botan::BlockCipher>("AES-256"));
   result.test_not_null("AES-256 can be created under FIPS", Botan::BlockCipher::create_or_throw("AES-256"));
   #endif
#endif

#if defined(BOTAN_HAS_HASH)
   result.test_throws<Botan::Algorithm_Not_Permitted>(
      "MD5 rejected at initialization", "'MD5' is not in the approved algorithm whitelist of policy 'FIPS 140-3'", [] {
         Botan::HashFunction::create_or_throw("MD5");
      });

   #if defined(BOTAN_HAS_SHA_256)
   result.test_not_null("SHA-256 can be created under FIPS", Botan::HashFunction::create_or_throw("SHA-256"));
   #endif
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
   result.test_throws<Botan::Algorithm_Not_Permitted>(
      "ChaCha20 rejected at initialization", "ChaCha20", [] { Botan::StreamCipher::create_or_throw("ChaCha20"); });
#endif

#if defined(BOTAN_HAS_MAC)
   // Composed algorithms are rejected if any component is not approved
   result.test_throws<Botan::Algorithm_Not_Permitted>(
      "HMAC(MD5) rejected at initialization", "component 'MD5' of 'HMAC(MD5)'", [] {
         Botan::MessageAuthenticationCode::create_or_throw("HMAC(MD5)");
      });

   #if defined(BOTAN_HAS_HMAC) && defined(BOTAN_HAS_SHA_256)
   result.test_not_null("HMAC(SHA-256) can be created under FIPS",
                        Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)"));
   #endif
#endif

#if defined(BOTAN_HAS_CIPHER_MODES)
   result.test_throws<Botan::Algorithm_Not_Permitted>(
      "Blowfish/CBC rejected at initialization", "component 'Blowfish' of 'Blowfish/CBC'", [] {
         Botan::Cipher_Mode::create_or_throw("Blowfish/CBC", Botan::Cipher_Dir::Encryption);
      });

   #if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_GCM)
   result.test_not_null("AES-256/GCM can be created under FIPS",
                        Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption));
   #endif
#endif

   return result;
}

Test::Result test_strict_policy() {
   Test::Result result("strict algorithm policy");

   const Scoped_Algorithm_Policy policy(Botan::Algorithm_Policy::strict());

   result.test_str_eq("active policy is strict", Botan::algorithm_policy().policy_name(), "strict");

   // Availability precheck
   result.test_is_true("strict permits AES-256", Botan::algorithm_permitted("AES-256"));
   result.test_is_true("strict permits SHA-256", Botan::algorithm_permitted("SHA-256"));
   result.test_is_true("strict permits ChaCha20", Botan::algorithm_permitted("ChaCha20"));
   result.test_is_true("strict permits AES-256/GCM", Botan::algorithm_permitted("AES-256/GCM"));
   result.test_is_false("strict rejects SHA-1", Botan::algorithm_permitted("SHA-1"));
   result.test_is_false("strict rejects MD5", Botan::algorithm_permitted("MD5"));
   result.test_is_false("strict rejects RC4", Botan::algorithm_permitted("RC4"));
   result.test_is_false("strict rejects CBC mode", Botan::algorithm_permitted("AES-256/CBC"));
   result.test_is_false("strict rejects Blowfish", Botan::algorithm_permitted("Blowfish"));

#if defined(BOTAN_HAS_CIPHER_MODES)
   // Legacy modes are rejected at initialization even though the cipher is approved
   try {
      Botan::Cipher_Mode::create_or_throw("AES-256/CBC", Botan::Cipher_Dir::Encryption);
      result.test_failure("AES-256/CBC was not rejected by the strict policy");
   } catch(const Botan::Algorithm_Not_Permitted& e) {
      result.test_str_contains("rejection names the algorithm", e.what(), "AES-256/CBC");
      result.test_str_contains("rejection names the rejected component", e.what(), "'CBC'");
      result.test_str_contains("rejection names the policy", e.what(), "strict");
      result.test_str_contains("rejection explains the reason", e.what(), "not in the approved algorithm whitelist");
   }

   #if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_GCM)
   result.test_not_null("AES-256/GCM can be created under strict",
                        Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption));
   #endif
#endif

#if defined(BOTAN_HAS_HASH)
   result.test_throws<Botan::Algorithm_Not_Permitted>(
      "SHA-1 rejected at initialization", "'SHA-1' is not in the approved algorithm whitelist of policy 'strict'", [] {
         Botan::HashFunction::create_or_throw("SHA-1");
      });

   #if defined(BOTAN_HAS_SHA_256)
   result.test_not_null("SHA-256 can be created under strict", Botan::HashFunction::create_or_throw("SHA-256"));
   #endif
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER) && defined(BOTAN_HAS_CHACHA)
   result.test_not_null("ChaCha20 can be created under strict", Botan::StreamCipher::create_or_throw("ChaCha20"));
#endif

   return result;
}

Test::Result test_custom_policy() {
   Test::Result result("custom algorithm policy");

   result.test_throws<Botan::Invalid_Argument>("custom policy requires a name",
                                               [] { Botan::Algorithm_Policy::custom("", {}); });

   const Scoped_Algorithm_Policy policy(
      Botan::Algorithm_Policy::custom("unit-test-policy", {"AES-256", "GCM", "SHA-256", "HMAC"}));

   result.test_str_eq("active policy is the custom one", Botan::algorithm_policy().policy_name(), "unit-test-policy");

   result.test_is_true("custom policy permits whitelisted AES-256", Botan::algorithm_permitted("AES-256"));
   result.test_is_true("custom policy permits whitelisted AES-256/GCM", Botan::algorithm_permitted("AES-256/GCM"));
   result.test_is_true("custom policy permits whitelisted HMAC(SHA-256)",
                       Botan::algorithm_permitted("HMAC(SHA-256)"));
   result.test_is_false("custom policy rejects AES-128", Botan::algorithm_permitted("AES-128"));
   result.test_is_false("custom policy rejects SHA-384", Botan::algorithm_permitted("SHA-384"));
   result.test_is_false("custom policy rejects AES-256/CBC", Botan::algorithm_permitted("AES-256/CBC"));

#if defined(BOTAN_HAS_BLOCK_CIPHER) && defined(BOTAN_HAS_AES)
   result.test_not_null("whitelisted AES-256 can be created", Botan::BlockCipher::create_or_throw("AES-256"));

   try {
      Botan::BlockCipher::create_or_throw("AES-128");
      result.test_failure("AES-128 was not rejected by the custom policy");
   } catch(const Botan::Algorithm_Not_Permitted& e) {
      result.test_str_contains("rejection names the algorithm", e.what(), "AES-128");
      result.test_str_contains("rejection names the policy", e.what(), "unit-test-policy");
      result.test_str_contains("rejection explains the reason", e.what(), "not in the approved algorithm whitelist");
   }
#endif

#if defined(BOTAN_HAS_CIPHER_MODES) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_GCM)
   result.test_not_null("whitelisted AES-256/GCM can be created",
                        Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption));
#endif

   return result;
}

class Algo_Policy_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         return {test_default_policy(), test_fips_policy(), test_strict_policy(), test_custom_policy()};
      }
};

}  // namespace

BOTAN_REGISTER_SERIALIZED_TEST("algo_policy", "algo_policy", Algo_Policy_Tests);

}  // namespace Botan_Tests
