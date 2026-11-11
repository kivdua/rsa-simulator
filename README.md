# RSA Simulator

Textbook RSA in a single Python file, printed one step at a time: key generation, encryption, decryption, signing, and an attack that factors the modulus to steal the private key.

No dependencies. Python 3.10 or newer.

> Educational only. There is no padding (OAEP or PSS), so this is not safe for real secrets.

## Run it

```bash
python rsa_sim.py                              # interactive menu
python rsa_sim.py demo                         # walkthrough with p = 61, q = 53
python rsa_sim.py demo --bits 64               # walkthrough with a random 64-bit key
python rsa_sim.py demo --p 61 --q 53 --e 17 --message "hi"
python rsa_sim.py crack 3233                   # factor a modulus, rebuild the key
```

## What the demo shows

| Step | What happens |
| --- | --- |
| 1 to 3 | Pick primes `p`, `q`, then compute `n = p * q` and `phi = (p - 1)(q - 1)` |
| 4 | Choose a public exponent `e` coprime to `phi` |
| 5 | Find `d = e^-1 mod phi` with the extended Euclidean algorithm, table printed |
| 6, 7 | Encrypt `c = m^e mod n` and decrypt `m = c^d mod n`, with every square and multiply step |
| 8 | Sign a SHA-256 hash with `d`, verify with `e`, then show a tampered message failing |
| 9 | Factor `n` with Pollard's rho and recover `d` from the public key alone |

Sample output:

```
5. Private exponent d = e^-1 mod phi (extended Euclid)
------------------------------------------------------
         q              r              s              t
                        7              1              0
                     3120              0              1
         0              7              1              0
       445              5           -445              1
         1              2            446             -1
         2              1          -1337              3
         2              0           3120             -7
  gcd = 1, so 7 * (-1337) = 1 (mod 3120)
  d = -1337 mod 3120 = 1783
```

## How it works

- **Primes**: random odd candidates tested with Miller-Rabin (40 rounds).
- **Modular inverse**: extended Euclid, no library call.
- **Exponentiation**: left-to-right square and multiply.
- **Text**: UTF-8 bytes are split into blocks that fit below `n`, each block encrypted on its own.
- **Attack**: Pollard's rho. A 64-bit modulus falls in well under a second, which is why real keys are 2048 bits or more. The simulator refuses to try above 100 bits.

## Why this is not real RSA

- No padding, so the same message always gives the same ciphertext, and small messages can be recovered directly.
- Each block is encrypted separately, which leaks patterns.
- Nothing is constant time, so it leaks through timing.

## Tests

```bash
python -m unittest -v
```
