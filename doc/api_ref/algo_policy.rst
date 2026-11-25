Algorithm Policies
========================================

.. versionadded:: 3.15.0

Some deployments (for example FIPS 140-3 validated environments) must ensure
that only a specific set of approved algorithms is used. Without a policy
mechanism, a request for an unavailable or non-approved algorithm is only
discovered when the algorithm is first used, typically deep inside the
application.

The algorithm policy facility (``botan/algo_policy.h``) allows installing a
process wide whitelist of permitted algorithms. Once a policy is active, the
algorithm factories (:cpp:class:`BlockCipher`, :cpp:class:`HashFunction`,
:cpp:class:`MessageAuthenticationCode`, :cpp:class:`StreamCipher` and
:cpp:class:`Cipher_Mode`) reject any algorithm that is not permitted, already
at object creation time:

* the non-throwing factory functions (``create``) return ``nullptr``
* the ``create_or_throw`` functions throw
  :cpp:class:`Algorithm_Not_Permitted`, whose message names the algorithm,
  the policy, and the reason for the rejection

Composed algorithm specifications such as "AES-256/GCM" or "HMAC(SHA-256)"
are checked component by component against the whitelist; purely numeric
components (key sizes, tag lengths and similar parameters) are ignored.

If no policy is installed, the default policy permits every algorithm
compiled into the library, which is exactly the behavior of previous
releases. Existing applications therefore do not need any changes.

.. cpp:class:: Botan::Algorithm_Policy

   .. cpp:function:: static Algorithm_Policy standard()

      The default policy: every algorithm compiled into the library is
      permitted.

   .. cpp:function:: static Algorithm_Policy fips_140()

      Permits only algorithms approved by FIPS 140-3 (AES, SHA-2, SHA-3,
      HMAC, CMAC, GCM, CBC, CTR, ...). Algorithms such as Blowfish, MD5,
      SHA-1, RC4 or ChaCha20 are rejected.

   .. cpp:function:: static Algorithm_Policy strict()

      Permits only modern algorithms with no known practical weaknesses
      (AES, SHA-2/SHA-3, BLAKE2b, HMAC, GCM, ChaCha20, ...). Legacy
      constructions such as CBC mode, SHA-1, MD5 and RC4 are rejected.

   .. cpp:function:: static Algorithm_Policy custom(std::string name, std::set<std::string> allowed)

      A policy with an application defined whitelist of algorithm names.

   .. cpp:function:: bool permits(std::string_view algo_spec) const

      Returns true if the algorithm specification is permitted by this policy.

   .. cpp:function:: std::string rejection_reason(std::string_view algo_spec) const

      Returns a human readable explanation of why the specification is
      rejected by this policy.

.. cpp:function:: void Botan::set_algorithm_policy(const Algorithm_Policy& policy)

   Installs the process wide policy. Intended to be called once during
   application initialization, before any algorithm objects are created.

.. cpp:function:: const Algorithm_Policy& Botan::algorithm_policy()

   Returns the currently active policy.

.. cpp:function:: bool Botan::algorithm_permitted(std::string_view algo_spec)

   Precheck: returns true if the active policy permits the specification.

.. cpp:function:: bool Botan::algorithm_available<Factory>(std::string_view algo_spec)

   Precheck: returns true if the specification is both permitted by the
   active policy and implemented by some provider compiled into the library,
   for example ``Botan::algorithm_available<Botan::BlockCipher>("AES-256")``.

Example
----------------------------------------

.. code-block:: cpp

   // During application initialization:
   Botan::set_algorithm_policy(Botan::Algorithm_Policy::fips_140());

   // Optional precheck, eg when reading an algorithm name from a config file:
   if(!Botan::algorithm_available<Botan::HashFunction>("MD5")) {
      // reject the configuration early, with a clear diagnostic
   }

   // Later, anywhere in the application:
   auto hash = Botan::HashFunction::create_or_throw("MD5");
   // throws Botan::Algorithm_Not_Permitted:
   // "Hash 'MD5' is not permitted by algorithm policy 'FIPS 140-3':
   //  'MD5' is not in the approved algorithm whitelist of policy 'FIPS 140-3'"
