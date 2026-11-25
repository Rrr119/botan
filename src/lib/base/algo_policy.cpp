/*
* Algorithm Availability Policies
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/algo_policy.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <algorithm>
#include <cctype>
#include <vector>

namespace Botan {

namespace {

/*
* Split a composed algorithm specification such as "AES-256/GCM" or
* "HMAC(SHA-256)" into its component names. Purely numeric components
* (key sizes, tag lengths, iteration counts, ...) are dropped since they
* are parameters, not algorithms.
*/
std::vector<std::string_view> algorithm_components(std::string_view algo_spec) {
   std::vector<std::string_view> components;

   size_t start = 0;
   const auto is_delim = [](char c) { return c == '/' || c == '(' || c == ')' || c == ','; };

   for(size_t i = 0; i <= algo_spec.size(); ++i) {
      if(i == algo_spec.size() || is_delim(algo_spec[i])) {
         const auto component = algo_spec.substr(start, i - start);
         start = i + 1;

         if(component.empty()) {
            continue;
         }

         const bool numeric = std::all_of(component.begin(), component.end(), [](char c) {
            return std::isdigit(static_cast<unsigned char>(c)) != 0;
         });

         if(!numeric) {
            components.push_back(component);
         }
      }
   }

   return components;
}

std::set<std::string> fips_140_whitelist() {
   // Algorithms approved for use by FIPS 140-3 (see NIST SP 800-140Cr1);
   // restricted to the symmetric algorithms, hashes, MACs and cipher
   // modes whose factories consult the algorithm policy.
   return {// Block ciphers
           "AES-128",
           "AES-192",
           "AES-256",
           // Hash functions
           "SHA-224",
           "SHA-256",
           "SHA-384",
           "SHA-512",
           "SHA-512-224",
           "SHA-512-256",
           "SHA3-224",
           "SHA3-256",
           "SHA3-384",
           "SHA3-512",
           "SHAKE-128",
           "SHAKE-256",
           // MACs
           "HMAC",
           "CMAC",
           "GMAC",
           // Cipher modes
           "CBC",
           "CFB",
           "OFB",
           "CTR",
           "CTR-BE",
           "CTR-LE",
           "ECB",
           "GCM",
           "CCM",
           "XTS",
           "KW",
           "KWP",
           // Block cipher padding schemes
           "PKCS7",
           "OneAndZeros",
           "X9.23"};
}

std::set<std::string> strict_whitelist() {
   // A conservative set of modern algorithms with no known practical
   // weaknesses; legacy constructions (CBC, SHA-1, MD5, RC4, ...) are
   // deliberately excluded.
   return {// Block ciphers
           "AES-128",
           "AES-192",
           "AES-256",
           // Hash functions
           "SHA-256",
           "SHA-384",
           "SHA-512",
           "SHA-512-256",
           "SHA3-256",
           "SHA3-384",
           "SHA3-512",
           "SHAKE-128",
           "SHAKE-256",
           "BLAKE2b",
           // MACs
           "HMAC",
           "CMAC",
           "Poly1305",
           // Stream ciphers
           "ChaCha20",
           // Cipher modes
           "CTR",
           "CTR-BE",
           "GCM",
           "OCB",
           "SIV",
           "EAX",
           "ChaCha20Poly1305"};
}

}  // namespace

Algorithm_Policy Algorithm_Policy::standard() {
   return Algorithm_Policy("standard", true, {});
}

Algorithm_Policy Algorithm_Policy::fips_140() {
   return Algorithm_Policy("FIPS 140-3", false, fips_140_whitelist());
}

Algorithm_Policy Algorithm_Policy::strict() {
   return Algorithm_Policy("strict", false, strict_whitelist());
}

Algorithm_Policy Algorithm_Policy::custom(std::string name, std::set<std::string> allowed) {
   if(name.empty()) {
      throw Invalid_Argument("Algorithm_Policy::custom requires a non-empty policy name");
   }
   return Algorithm_Policy(std::move(name), false, std::move(allowed));
}

Algorithm_Policy::Algorithm_Policy(std::string name, bool permit_all, std::set<std::string> allowed) :
      m_name(std::move(name)), m_permit_all(permit_all), m_allowed(std::move(allowed)) {}

bool Algorithm_Policy::permits(std::string_view algo_spec) const {
   if(m_permit_all) {
      return true;
   }

   for(const auto& component : algorithm_components(algo_spec)) {
      if(m_allowed.contains(std::string(component)) == false) {
         return false;
      }
   }

   return true;
}

std::string Algorithm_Policy::rejection_reason(std::string_view algo_spec) const {
   if(m_permit_all) {
      return "algorithm is permitted";
   }

   for(const auto& component : algorithm_components(algo_spec)) {
      if(m_allowed.contains(std::string(component)) == false) {
         if(component == algo_spec) {
            return fmt("'{}' is not in the approved algorithm whitelist of policy '{}'", component, m_name);
         }
         return fmt("component '{}' of '{}' is not in the approved algorithm whitelist of policy '{}'",
                    component,
                    algo_spec,
                    m_name);
      }
   }

   return "algorithm is permitted";
}

namespace {

Algorithm_Policy& mutable_active_policy() {
   // The default policy permits everything, matching the behavior of
   // previous releases.
   static Algorithm_Policy active_policy = Algorithm_Policy::standard();
   return active_policy;
}

}  // namespace

void set_algorithm_policy(const Algorithm_Policy& policy) {
   mutable_active_policy() = policy;
}

const Algorithm_Policy& algorithm_policy() {
   return mutable_active_policy();
}

void throw_if_algorithm_not_permitted(std::string_view algo_type, std::string_view algo_spec) {
   const Algorithm_Policy& policy = algorithm_policy();

   if(!policy.permits(algo_spec)) {
      throw Algorithm_Not_Permitted(algo_type, algo_spec, policy.policy_name(), policy.rejection_reason(algo_spec));
   }
}

}  // namespace Botan
