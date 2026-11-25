/*
* Algorithm Availability Policies
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ALGO_POLICY_H_
#define BOTAN_ALGO_POLICY_H_

#include <botan/types.h>
#include <set>
#include <string>
#include <string_view>

namespace Botan {

/**
* An algorithm policy decides which algorithms an application is willing to
* use. Each policy carries a whitelist of approved algorithm names; composed
* algorithm specifications (such as "AES-256/GCM" or "HMAC(SHA-256)") are
* checked component by component against that whitelist.
*
* A policy can be installed process wide with set_algorithm_policy(), in
* which case the algorithm factories (BlockCipher, HashFunction,
* MessageAuthenticationCode, StreamCipher, Cipher_Mode) reject any algorithm
* that is not permitted, already at object creation time. The non-throwing
* factory functions return nullptr for a rejected algorithm, while the
* create_or_throw() functions throw Algorithm_Not_Permitted with a message
* explaining why the algorithm was rejected.
*
* The default policy is Algorithm_Policy::standard(), which permits every
* algorithm compiled into the library, preserving the historical behavior.
*/
class BOTAN_PUBLIC_API(3, 15) Algorithm_Policy final {
   public:
      /**
      * The default policy: every algorithm compiled into the library is
      * permitted. This is equivalent to the behavior of previous releases.
      */
      static Algorithm_Policy standard();

      /**
      * A policy permitting only algorithms approved by FIPS 140-3
      * (eg AES, SHA-2, SHA-3, HMAC, CMAC, GCM, CBC, CTR, ...).
      * Algorithms such as Blowfish, MD5, SHA-1, RC4 or ChaCha20 are rejected.
      */
      static Algorithm_Policy fips_140();

      /**
      * A conservative policy permitting only modern algorithms with no
      * known practical weaknesses (eg AES, SHA-2/SHA-3, BLAKE2b, HMAC,
      * GCM, ChaCha20). Legacy constructions such as CBC or CCM mode,
      * SHA-1, MD5 and RC4 are rejected.
      */
      static Algorithm_Policy strict();

      /**
      * A policy with an application defined whitelist.
      *
      * @param name a name for the policy, used in error messages
      * @param allowed the whitelist of permitted algorithm names; composed
      *        specifications are permitted only if every component appears
      *        in the whitelist
      */
      static Algorithm_Policy custom(std::string name, std::set<std::string> allowed);

      /**
      * @return the name of this policy
      */
      std::string_view policy_name() const { return m_name; }

      /**
      * Check if an algorithm specification is permitted by this policy.
      *
      * Composed specifications (eg "AES-256/GCM" or "HMAC(SHA-256)") are
      * split into their components and each component is checked against
      * the whitelist. Purely numeric components (key sizes, tag lengths,
      * iteration counts and similar parameters) are ignored.
      *
      * @param algo_spec the algorithm specification to check
      * @return true if the specification is permitted by this policy
      */
      bool permits(std::string_view algo_spec) const;

      /**
      * Return a human readable explanation of why an algorithm
      * specification is rejected by this policy.
      *
      * @param algo_spec the algorithm specification that was rejected
      * @return the reason for the rejection
      */
      std::string rejection_reason(std::string_view algo_spec) const;

   private:
      Algorithm_Policy(std::string name, bool permit_all, std::set<std::string> allowed);

      std::string m_name;
      bool m_permit_all;
      std::set<std::string> m_allowed;
};

/**
* Install the process wide algorithm policy. The factories consult this
* policy whenever an algorithm object is created.
*
* This is intended to be called once, during application initialization,
* before any algorithm objects are created. It is not thread safe with
* respect to concurrent algorithm creation.
*
* @param policy the policy to activate
*/
void BOTAN_PUBLIC_API(3, 15) set_algorithm_policy(const Algorithm_Policy& policy);

/**
* @return the currently active process wide algorithm policy
*/
BOTAN_PUBLIC_API(3, 15) const Algorithm_Policy& algorithm_policy();

/**
* Precheck if an algorithm specification is permitted by the currently
* active algorithm policy.
*
* @param algo_spec the algorithm specification to check
* @return true if the active policy permits the specification
*/
inline bool algorithm_permitted(std::string_view algo_spec) {
   return algorithm_policy().permits(algo_spec);
}

/**
* Precheck if an algorithm is usable: it must both be permitted by the
* currently active algorithm policy and be implemented by some provider
* compiled into the library.
*
* For example `algorithm_available<Botan::BlockCipher>("AES-256")`
*
* @param algo_spec the algorithm specification to check
* @return true if the algorithm can be created under the active policy
*/
template <typename Factory>
bool algorithm_available(std::string_view algo_spec) {
   return algorithm_permitted(algo_spec) && !Factory::providers(algo_spec).empty();
}

/**
* Throw Algorithm_Not_Permitted if the given algorithm specification is
* not permitted by the currently active algorithm policy. Does nothing
* if the algorithm is permitted.
*
* @param algo_type a description of the kind of algorithm (eg "Block cipher"),
*        used in the exception message
* @param algo_spec the algorithm specification to check
*/
void BOTAN_PUBLIC_API(3, 15) throw_if_algorithm_not_permitted(std::string_view algo_type, std::string_view algo_spec);

}  // namespace Botan

#endif
