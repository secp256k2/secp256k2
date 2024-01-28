<meta http-equiv="refresh" content="0; url=https://secp256k2.readthedocs.io/en/latest/">
# SECP256k2: A Modern Library for Elliptic Curve Cryptography

## Introduction

**SECP256k2** is a high-performance and easy-to-use library for working with the SECP256k1 elliptic curve. This library is meticulously designed to provide a robust set of functionalities needed for the development of secure, fast, and efficient cryptographic applications.

## Features

- **Optimized Performance:** Leveraging optimized algorithms and efficient code structures for high-speed operations on the SECP256k1 curve.
- **Comprehensive Toolset:** Offering a wide array of functionalities ranging from basic arithmetic operations to advanced cryptographic protocols.
- **Cross-Platform:** Written in [your programming language], SECP256k2 is designed to be used on multiple operating systems including Windows and Linux.

## Getting Started

### Installation

#### windows with `pip`
```bash
pip install secp256k2
```

#### linux and Mac with `pip3`
```bash
pip3 install secp256k2
```

### Usage

A quick example to get you started with SECP256k2:

```python
from secp256k2 import Contactor

cont = Contactor()

dec = 0x00000000000000000000000000000000000000000000001

wif_compress = cont.Decimal_To_Wif(dec, True)

wif_uncompress = cont.Decimal_To_Wif(dec, False)

```
---

compressed and uncompressed bitcoin address wallet from decimal (integer).

```python
from secp256k2 import Contactor
# added Contactor class to project script
co = Contactor()
# dec
dec = 0xffffffffffffffffffffff880000000000000
compress_address = co.Decimal_To_Addr(dec, addr_type=0, compress=True)
uncompress_address = co.Decimal_To_Addr(dec, addr_type=0, compress=False)
```
---

Convert Decimal (Number) To Ethereum Address (Maximum Range: `115792089237316195423570985008687907852837564279074904382605163141518161494337`):

```python
from secp256k2 import Contactor

cont = Contactor()

dec_num = 1 # example , can use any range number to 
# ethereum address generated from decimal number 
eth_address = cont.Decimal_To_ETH_Addr(dec_num)
```
---
convert and Generated Wif Key from decimal Number:
```python
from secp256k2 import Contactor

co = Contactor()

dec = 0xffffffffffffffffffffffffff8999999999333666666
wif_compress = co.Decimal_To_Wif(dec, True)
wif_uncompress = co.Decimal_To_Wif(dec, False)
```
---
Decimal to RIPEMD160

```python
from secp256k2 import Contactor

co = Contactor()

dec = 0xfffffffffffffffffff99999999999

ripemd160 = co.Decimal_To_RIPEMD160(dec)
```
---
convert wif key to private key (hex):

```python
from secp256k2 import Contactor

co = Contactor()

WIF = "WIF_KEY_HERE"

privatekey = co.Wif_To_Hex(WIF)
```

## Documentation

For more detailed information and advanced usage, please refer to the [full documentation](https://secp256k2.github.io/secp256k2).

## Contribution

We welcome contributions from the open-source community. If you find any issues or would like to propose enhancements, please feel free to open an issue or submit a pull request.

## License

SECP256k2 is licensed under MIT. For more information, please see the [LICENSE](/LICENSE) file.

---

### Donate:

Bitcoin:`1MMDRZA12xdBLD1P5AfEfvEMErp588vmF9`


Programmer And Owner : [PyMmdrza](https://github.com/Pymmdrza)

official website : <a title="official website programmer" href="https://mmdrza.com/" rel="follow">MMDRZA.COM</a>
