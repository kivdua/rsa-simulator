#!/usr/bin/env python3
"""RSA simulator: textbook RSA shown one step at a time.

Educational only. There is no padding (OAEP/PSS), so nothing here is safe
for real secrets. Use the `cryptography` package for that.

Usage:
    python rsa_sim.py                      interactive menu
    python rsa_sim.py demo                 walkthrough with the classic p=61, q=53
    python rsa_sim.py demo --bits 64       walkthrough with random 64-bit keys
    python rsa_sim.py demo --p 61 --q 53 --message "hi"
    python rsa_sim.py crack 3233           factor a modulus and rebuild the private key
"""
from __future__ import annotations

import argparse
import hashlib
import math
import secrets
import sys
import time
from dataclasses import dataclass

# --------------------------------------------------------------------------
# Number theory
# --------------------------------------------------------------------------

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits: int) -> int:
    """Random prime with exactly `bits` bits."""
    if bits < 4:
        raise ValueError("need at least 4 bits per prime")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def egcd_steps(a: int, b: int):
    """Extended Euclid. Returns (g, x, y, rows) with a*x + b*y == g.

    Each row is (q, r, s, t): quotient, remainder and the running
    coefficients, so the table can be printed.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    rows = [(None, old_r, old_s, old_t), (None, r, s, t)]
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
        rows.append((q, r, s, t))
    return old_r, old_s, old_t, rows


def modinv(a: int, m: int) -> int:
    g, x, _, _ = egcd_steps(a, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m} (gcd is {g})")
    return x % m


def modpow_steps(base: int, exp: int, mod: int):
    """Left-to-right square and multiply. Returns (result, rows).

    Each row is (bit, after_square, after_multiply_or_None).
    """
    result = 1
    rows = []
    for bit in bin(exp)[2:]:
        squared = result * result % mod
        if bit == "1":
            result = squared * base % mod
            rows.append((bit, squared, result))
        else:
            result = squared
            rows.append((bit, squared, None))
    return result, rows


def pollard_rho(n: int) -> int:
    """Return a non-trivial factor of composite n."""
    if n % 2 == 0:
        return 2
    while True:
        c = secrets.randbelow(n - 1) + 1
        x = y = secrets.randbelow(n - 2) + 2
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def factor_semiprime(n: int):
    """Split n = p*q. Returns (p, q) with p <= q."""
    if n < 4 or is_probable_prime(n):
        raise ValueError(f"{n} is not a product of two primes")
    p = pollard_rho(n)
    q = n // p
    return (p, q) if p <= q else (q, p)


# --------------------------------------------------------------------------
# RSA
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyPair:
    p: int
    q: int
    n: int
    phi: int
    e: int
    d: int

    @property
    def public(self):
        return (self.e, self.n)

    @property
    def private(self):
        return (self.d, self.n)


def choose_e(phi: int) -> int:
    """65537 when it fits, otherwise the smallest odd e coprime to phi."""
    if phi > 65537 and math.gcd(65537, phi) == 1:
        return 65537
    e = 3
    while e < phi:
        if math.gcd(e, phi) == 1:
            return e
        e += 2
    raise ValueError("no valid public exponent; pick larger primes")


def make_keypair(p: int, q: int, e: int | None = None) -> KeyPair:
    if not is_probable_prime(p):
        raise ValueError(f"p = {p} is not prime")
    if not is_probable_prime(q):
        raise ValueError(f"q = {q} is not prime")
    if p == q:
        raise ValueError("p and q must be different")
    n = p * q
    phi = (p - 1) * (q - 1)
    if e is None:
        e = choose_e(phi)
    if not 1 < e < phi:
        raise ValueError(f"e must satisfy 1 < e < phi ({phi})")
    if math.gcd(e, phi) != 1:
        raise ValueError(f"e = {e} shares a factor with phi = {phi}")
    return KeyPair(p, q, n, phi, e, modinv(e, phi))


def generate_keypair(bits: int) -> KeyPair:
    """Random key with a modulus of roughly `bits` bits."""
    if bits < 16:
        raise ValueError("modulus needs at least 16 bits")
    half = bits // 2
    while True:
        p = random_prime(half)
        q = random_prime(bits - half)
        if p == q:
            continue
        try:
            return make_keypair(p, q)
        except ValueError:
            continue


def encrypt_int(m: int, e: int, n: int) -> int:
    if not 0 <= m < n:
        raise ValueError(f"message {m} must be in the range 0..{n - 1}")
    return pow(m, e, n)


def decrypt_int(c: int, d: int, n: int) -> int:
    if not 0 <= c < n:
        raise ValueError(f"ciphertext {c} must be in the range 0..{n - 1}")
    return pow(c, d, n)


def block_size(n: int) -> int:
    """Bytes of plaintext that always fit below n."""
    return (n.bit_length() - 1) // 8


def text_to_blocks(text: str, n: int) -> list[int]:
    size = block_size(n)
    if size < 1:
        raise ValueError("n must be at least 256 to encrypt text; use bigger primes")
    data = text.encode("utf-8")
    return [int.from_bytes(data[i:i + size], "big") for i in range(0, len(data), size)]


def blocks_to_text(blocks: list[int]) -> str:
    data = b"".join(b.to_bytes(max(1, (b.bit_length() + 7) // 8), "big") for b in blocks)
    return data.decode("utf-8", errors="replace")


def encrypt_text(text: str, e: int, n: int) -> list[int]:
    return [encrypt_int(m, e, n) for m in text_to_blocks(text, n)]


def decrypt_text(cipher: list[int], d: int, n: int) -> str:
    return blocks_to_text([decrypt_int(c, d, n) for c in cipher])


def message_hash(text: str, n: int) -> int:
    """SHA-256 of the message, reduced mod n so it fits the key."""
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest(), "big") % n


def sign(text: str, d: int, n: int) -> int:
    return pow(message_hash(text, n), d, n)


def verify(text: str, signature: int, e: int, n: int) -> bool:
    return pow(signature, e, n) == message_hash(text, n)


# --------------------------------------------------------------------------
# Display
# --------------------------------------------------------------------------


def fmt(x: int) -> str:
    """Shorten very long numbers so tables stay readable."""
    s = str(x)
    if len(s) <= 40:
        return s
    return f"{s[:12]}...{s[-12:]} ({len(s)} digits)"


def heading(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def show_egcd(e: int, phi: int) -> None:
    g, x, _, rows = egcd_steps(e, phi)
    if len(rows) > 24:
        print(f"  ({len(rows) - 2} division steps, table hidden)")
    else:
        print(f"  {'q':>8} {'r':>14} {'s':>14} {'t':>14}")
        for q, r, s, t in rows:
            print(f"  {'' if q is None else q:>8} {r:>14} {s:>14} {t:>14}")
    print(f"  gcd = {g}, so {fmt(e)} * ({fmt(x)}) = 1 (mod {fmt(phi)})")
    print(f"  d = {fmt(x)} mod {fmt(phi)} = {fmt(x % phi)}")


def show_modpow(base: int, exp: int, mod: int, label: str) -> int:
    result, rows = modpow_steps(base, exp, mod)
    print(f"  {label}: {fmt(base)}^{fmt(exp)} mod {fmt(mod)}")
    if len(rows) > 24:
        print(f"  ({len(rows)} square steps, table hidden)")
    else:
        print(f"  exponent in binary: {bin(exp)[2:]}")
        print(f"  {'bit':>5} {'square':>14} {'multiply':>14}")
        for bit, squared, multiplied in rows:
            print(f"  {bit:>5} {squared:>14} {'' if multiplied is None else multiplied:>14}")
    print(f"  result = {fmt(result)}")
    return result


def show_keys(key: KeyPair) -> None:
    print(f"  p   = {fmt(key.p)}")
    print(f"  q   = {fmt(key.q)}")
    print(f"  n   = {fmt(key.n)}  ({key.n.bit_length()} bits)")
    print(f"  phi = {fmt(key.phi)}")
    print(f"  public key  (e, n) = ({fmt(key.e)}, {fmt(key.n)})")
    print(f"  private key (d, n) = ({fmt(key.d)}, {fmt(key.n)})")


def run_crack(n: int) -> KeyPair | None:
    """Factor n and show how the private key falls out."""
    bits = n.bit_length()
    if bits > 100:
        print(f"  n has {bits} bits. Pollard's rho would take far too long, which is the point.")
        return None
    start = time.perf_counter()
    try:
        p, q = factor_semiprime(n)
    except ValueError as err:
        print(f"  {err}")
        return None
    elapsed = time.perf_counter() - start
    print(f"  n = {n} = {p} * {q}   (found in {elapsed * 1000:.2f} ms)")
    return make_keypair(p, q) if is_probable_prime(p) and is_probable_prime(q) and p != q else None


def run_demo(p: int | None, q: int | None, e: int | None, bits: int | None, message: str) -> None:
    heading("1. Pick two primes")
    if bits:
        key = generate_keypair(bits)
        if e is not None:
            key = make_keypair(key.p, key.q, e)
    else:
        key = make_keypair(p or 61, q or 53, e)
    print(f"  p = {fmt(key.p)}\n  q = {fmt(key.q)}")

    heading("2. Modulus n = p * q")
    print(f"  n = {fmt(key.n)}  ({key.n.bit_length()} bits)")

    heading("3. Totient phi = (p - 1)(q - 1)")
    print(f"  phi = {fmt(key.phi)}")

    heading("4. Public exponent e, coprime to phi")
    print(f"  e = {key.e}, gcd(e, phi) = {math.gcd(key.e, key.phi)}")

    heading("5. Private exponent d = e^-1 mod phi (extended Euclid)")
    show_egcd(key.e, key.phi)

    heading("6. Encrypt: c = m^e mod n")
    blocks = text_to_blocks(message, key.n)
    print(f"  message {message!r} as {block_size(key.n)}-byte blocks: {[fmt(b) for b in blocks]}")
    cipher = [encrypt_int(m, key.e, key.n) for m in blocks]
    show_modpow(blocks[0], key.e, key.n, "first block")
    print(f"  ciphertext: {[fmt(c) for c in cipher]}")

    heading("7. Decrypt: m = c^d mod n")
    show_modpow(cipher[0], key.d, key.n, "first block")
    recovered = decrypt_text(cipher, key.d, key.n)
    print(f"  recovered message: {recovered!r}")

    heading("8. Sign with d, verify with e")
    h = message_hash(message, key.n)
    s = sign(message, key.d, key.n)
    print(f"  h = SHA-256(message) mod n = {fmt(h)}")
    print(f"  signature s = h^d mod n = {fmt(s)}")
    print(f"  s^e mod n = {fmt(pow(s, key.e, key.n))}  ->  valid: {verify(message, s, key.e, key.n)}")
    print(f"  tampered message valid: {verify(message + '!', s, key.e, key.n)}")

    heading("9. Attack: factor n from the public key alone")
    cracked = run_crack(key.n)
    if cracked:
        stolen = modinv(key.e, cracked.phi)
        print(f"  rebuilt d = {fmt(stolen)}  ->  matches the real d: {stolen == key.d}")
        print("  Small keys break instantly. Real keys use 2048 bits or more.")


# --------------------------------------------------------------------------
# Interactive menu
# --------------------------------------------------------------------------

MENU = """
1  Generate random keys          5  Sign a message
2  Enter my own primes           6  Verify a signature
3  Encrypt text                  7  Crack the current modulus
4  Decrypt ciphertext            8  Show keys
0  Quit"""


def ask_int(prompt: str) -> int:
    return int(input(prompt).strip().replace(",", ""))


def interactive() -> None:
    key = make_keypair(61, 53)
    print("RSA simulator. Starting with the classic p = 61, q = 53.")
    while True:
        print(MENU)
        try:
            choice = input("> ").strip()
            if choice == "0":
                return
            if choice == "1":
                key = generate_keypair(ask_int("modulus size in bits (e.g. 32, 64, 1024): "))
                show_keys(key)
            elif choice == "2":
                key = make_keypair(ask_int("p: "), ask_int("q: "))
                show_keys(key)
            elif choice == "3":
                cipher = encrypt_text(input("text: "), key.e, key.n)
                print("  ciphertext:", " ".join(map(str, cipher)))
            elif choice == "4":
                cipher = [int(c) for c in input("ciphertext blocks, space separated: ").split()]
                print(f"  plaintext: {decrypt_text(cipher, key.d, key.n)!r}")
            elif choice == "5":
                print("  signature:", sign(input("message: "), key.d, key.n))
            elif choice == "6":
                text = input("message: ")
                print("  valid:", verify(text, ask_int("signature: "), key.e, key.n))
            elif choice == "7":
                run_crack(key.n)
            elif choice == "8":
                show_keys(key)
            else:
                print("  pick a number from the menu")
        except ValueError as err:
            print(f"  error: {err}")
        except (EOFError, KeyboardInterrupt):
            print()
            return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Step-by-step textbook RSA simulator.")
    sub = parser.add_subparsers(dest="command")

    demo = sub.add_parser("demo", help="full walkthrough from key generation to attack")
    demo.add_argument("--p", type=int, help="first prime (default 61)")
    demo.add_argument("--q", type=int, help="second prime (default 53)")
    demo.add_argument("--e", type=int, help="public exponent (default: chosen for you)")
    demo.add_argument("--bits", type=int, help="generate a random modulus of this size instead")
    demo.add_argument("--message", default="RSA", help="text to encrypt and sign")

    crack = sub.add_parser("crack", help="factor a modulus n")
    crack.add_argument("n", type=int)

    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            if args.bits and (args.p or args.q):
                parser.error("use either --bits or --p/--q, not both")
            run_demo(args.p, args.q, args.e, args.bits, args.message)
        elif args.command == "crack":
            key = run_crack(args.n)
            if key:
                show_keys(key)
        else:
            interactive()
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
