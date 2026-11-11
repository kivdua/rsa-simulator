"""Tests for rsa_sim. Run with: python -m unittest -v"""
import math
import unittest

import rsa_sim as rsa


class NumberTheory(unittest.TestCase):
    def test_primality(self):
        primes = [2, 3, 5, 61, 53, 7919, 2**61 - 1]
        composites = [0, 1, 4, 561, 1105, 3233, 2**61 + 1]  # 561, 1105 are Carmichael numbers
        for p in primes:
            self.assertTrue(rsa.is_probable_prime(p), p)
        for c in composites:
            self.assertFalse(rsa.is_probable_prime(c), c)

    def test_random_prime_has_exact_size(self):
        for bits in (8, 16, 64):
            p = rsa.random_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(rsa.is_probable_prime(p))

    def test_egcd_identity(self):
        for a, b in [(7, 3120), (240, 46), (65537, 3120), (17, 5)]:
            g, x, y, _ = rsa.egcd_steps(a, b)
            self.assertEqual(g, math.gcd(a, b))
            self.assertEqual(a * x + b * y, g)

    def test_modinv(self):
        self.assertEqual(rsa.modinv(7, 3120), 1783)
        self.assertEqual(rsa.modinv(17, 3120), 2753)
        with self.assertRaises(ValueError):
            rsa.modinv(6, 3120)

    def test_modpow_matches_builtin(self):
        for base, exp, mod in [(65, 17, 3233), (2, 1, 7), (123456789, 65537, 10**18 + 9), (5, 0, 13)]:
            result, _ = rsa.modpow_steps(base, exp, mod)
            self.assertEqual(result, pow(base, exp, mod))

    def test_factor_semiprime(self):
        self.assertEqual(rsa.factor_semiprime(3233), (53, 61))
        p, q = rsa.random_prime(28), rsa.random_prime(30)
        self.assertEqual(rsa.factor_semiprime(p * q), (min(p, q), max(p, q)))
        with self.assertRaises(ValueError):
            rsa.factor_semiprime(61)


class Rsa(unittest.TestCase):
    def test_classic_example(self):
        key = rsa.make_keypair(61, 53, e=17)
        self.assertEqual((key.n, key.phi, key.d), (3233, 3120, 2753))
        self.assertEqual(rsa.encrypt_int(65, key.e, key.n), 2790)
        self.assertEqual(rsa.decrypt_int(2790, key.d, key.n), 65)

    def test_rejects_bad_keys(self):
        for p, q, e in [(60, 53, None), (61, 61, None), (61, 53, 6), (61, 53, 1)]:
            with self.assertRaises(ValueError):
                rsa.make_keypair(p, q, e)

    def test_message_must_be_below_n(self):
        with self.assertRaises(ValueError):
            rsa.encrypt_int(3233, 17, 3233)

    def test_text_round_trip(self):
        text = "Hello, RSA! é中 \U0001f510"
        for bits in (16, 32, 64, 512):
            key = rsa.generate_keypair(bits)
            self.assertEqual(key.n.bit_length() in (bits - 1, bits), True)
            cipher = rsa.encrypt_text(text, key.e, key.n)
            self.assertEqual(rsa.decrypt_text(cipher, key.d, key.n), text)

    def test_text_needs_big_enough_modulus(self):
        key = rsa.make_keypair(11, 13)
        with self.assertRaises(ValueError):
            rsa.encrypt_text("hi", key.e, key.n)

    def test_sign_and_verify(self):
        key = rsa.generate_keypair(256)
        s = rsa.sign("pay Bob 10", key.d, key.n)
        self.assertTrue(rsa.verify("pay Bob 10", s, key.e, key.n))
        self.assertFalse(rsa.verify("pay Bob 1000", s, key.e, key.n))
        self.assertFalse(rsa.verify("pay Bob 10", (s + 1) % key.n, key.e, key.n))

    def test_cracked_key_matches(self):
        key = rsa.generate_keypair(48)
        p, q = rsa.factor_semiprime(key.n)
        self.assertEqual(rsa.modinv(key.e, (p - 1) * (q - 1)), key.d)

    def test_cli(self):
        self.assertEqual(rsa.main(["demo"]), 0)
        self.assertEqual(rsa.main(["demo", "--bits", "64", "--message", "hello"]), 0)
        self.assertEqual(rsa.main(["crack", "3233"]), 0)
        self.assertEqual(rsa.main(["demo", "--p", "60", "--q", "53"]), 1)


if __name__ == "__main__":
    unittest.main()
