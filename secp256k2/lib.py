import os
import sys
import ctypes

import math, pickle
from .constants import (
    MAX_HEX,
    MAX_DEC,
    ZERO_BYTE,
    BASE58_CHARS,
    PREFIX_0,
    PREFIX_80,
    PREFIX_9,
    PREFIX_8,
    PREFIX_7,
    PREFIX_6,
    PREFIX_5,
    PREFIX_4,
    PREFIX_3,
    PREFIX_2,
    PREFIX_1
)
from .Loader import Load_cPack
from . import utils

Fuzz = Load_cPack()

for func_name, args in utils.argtypes_dict.items():
    getattr(Fuzz, func_name).argtypes = args

for func_name, restype in utils.restype_dict.items():
    getattr(Fuzz, func_name).restype = restype

Fuzz.init_secp256_lib()


class Base58k1:

    def __init__(self):
        super().__init__()

    # =============================================================================

    @staticmethod
    def fuzz256k1(result):
        return ctypes.cast(result, ctypes.c_char_p).value.decode('utf8')

    def b58py(self, data):
        B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        if data[0] == 0:
            return "1" + self.b58py(data[1:])

        x = sum([v * (256 ** i) for i, v in enumerate(data[::-1])])
        ret = ""
        while x > 0:
            ret = B58[x % 58] + ret
            x = x // 58

        return ret

    # ==============================================================================
    def b58_encode(self, inp_bytes):
        res = Fuzz.b58_encode(inp_bytes, len(inp_bytes))
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return addr

    # ==============================================================================
    def b58_decode(self, inp):
        res = Fuzz.b58_decode(inp.encode("utf-8"))
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return addr


def get_sha256(input_bytes):
    digest_bytes = PREFIX_0 * 32
    if type(input_bytes) == str:
        input_bytes = input_bytes.encode("utf-8")
    #    MiniKey example
    Fuzz.get_sha256(input_bytes, len(input_bytes), digest_bytes)
    return digest_bytes


def fl(s, length=64):
    fixed = None
    if type(s) == int:
        fixed = hex(s)[2:].zfill(length)
    elif type(s) == str:
        fixed = s[2:].zfill(length) if s[:2].lower() == '0x' else s.zfill(length)
    elif type(s) == bytes:
        fixed = PREFIX_0 * 32 - len(s) + s
    else:
        ValueError("[Error] Input format [Integer] [Hex] [Bytes] allowed only. Detected : ", type(s))
    return fixed


class Contactor:
    def __init__(self):
        super(Contactor, self).__init__()
        self.b58k1 = Base58k1()

    # ==============================================================================

    def version(self):
        Fuzz.version()

    # ==============================================================================
    def fuzz256k1(self, result):
        return ctypes.cast(result, ctypes.c_char_p).value.decode('utf8')

    # ==============================================================================
    def Decimal_To_Addr(self, decimal, addr_type: int, compress: bool = True):
        if decimal < 0:
            decimal = MAX_HEX + decimal
        pass_int_value = fl(decimal).encode('utf-8')
        res = Fuzz.privatekey_to_address(addr_type, compress, pass_int_value)
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return addr

    # =============================================================================
    def Decimal_To_Wif(self, decimal, compress=True):
        inp = ''
        suff = '01' if compress == True else ''
        if type(decimal) in [int, str]:
            inp = bytes.fromhex('80' + fl(decimal) + suff)
        elif type(decimal) == bytes:
            inp = b'\x80' + fl(decimal) + bytes.fromhex(suff)
        else:
            ValueError("[Error] Input format [Integer] [Hex] [Bytes] allowed only. Detected : ", type(decimal))
        if inp != '':
            res = get_sha256(get_sha256(inp))
            return self.b58k1.b58_encode(inp + res[:4])
        else:
            return inp

    # ==============================================================================
    @staticmethod
    def Decimal_To_RIPEMD160(dec, addr_type, compress=True):
        if dec < 0:
            dec = MAX_HEX + dec
        pass_int_value = fl(dec).encode('utf8')
        res = PREFIX_0 * 20
        Fuzz.privatekey_to_h160(addr_type, compress, pass_int_value, res)
        return res

    # ==============================================================================
    def Decimal_To_RIPEMD160_DIGEST(self, dec, addr_type, compress=True):
        res = self.Decimal_To_RIPEMD160(dec, addr_type, compress)
        return self.byter(res)

    # ==============================================================================
    def Decimal_To_ETH_Addr(self, dec):
        if dec < 0: dec = MAX_HEX + dec
        pass_int_value = fl(dec).encode('utf8')
        res = Fuzz.privatekey_to_ETH_address(pass_int_value)
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return '0x' + addr

    # ==============================================================================

    @staticmethod
    def Decimal_To_ETH_Addr_Bytes(self, dec):
        res = PREFIX_0 * 20
        Fuzz.privatekey_to_ETH_address_bytes(dec, res)
        return res

    # ==============================================================================

    def Decimal_To_ETH_Addr_Digest(self, dec):
        """ Privatekey Integer value passed to function. Output is 20 bytes ETH address lowercase without 0x"""
        if dec < 0: dec = MAX_HEX + dec
        pass_int_value = fl(dec).encode('utf8')
        res = self.Decimal_To_ETH_Addr_Bytes(pass_int_value)
        return self.byter(res)

    # =============================================================================

    def Decimal_To_Batch_ETH_Addr(self, dec, m):
        """

        Starting Privatekey Integer value passed to function as pvk_int.
        Integer m is, how many times sequential increment is done from the starting key.
        Output is bytes 20*m of ETH address lowercase without 0x as hex string

        """
        if m <= 0: m = 1
        if dec < 0: dec = MAX_HEX + dec
        start_pvk = fl(dec).encode('utf8')
        res = Fuzz.privatekey_group_to_ETH_address(start_pvk, m)
        addrlist = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return addrlist

    # ==============================================================================
    def RIPEMD160_To_Addr(self, hash160, addr_type, compress: bool = True):
        """
        Convert RIPEMD160 (Hash160) To Compressed and Uncompressed Address (addr_type: 0=p2pkh, 1=p2sh, 2=bech32)

        :param hash160:
        :param addr_type:
        :type addr_type: int.
        :param compress:
        :type compress: bool.
        :return address:
        :rtype: str.

        ---------------------------------------------------------------------------

        >>> ripemd160 = b'YOUR_HASH160' # example
        >>> compress_address = self.RIPEMD160_To_Addr(ripemd160, 0, True)
        >>> uncompress_address = self.RIPEMD160_To_Addr(ripemd160, 0, False)
        >>> # p2sh valid just compressed key
        >>> compress_p2sh = self.RIPEMD160_To_Addr(ripemd160, 1, True)
        >>> # bech32 valid just compressed key
        >>> compress_bech32 = self.RIPEMD160_To_Addr(ripemd160, 2, True)

        -----------------------------------------------------------------------------


        """
        res = Fuzz.hash_to_address(addr_type, compress, hash160)
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return addr

    # ==============================================================================
    def Wif_To_Hex(self, wif):

        """

        Converts a WIF Key to Hex.

        :param wif:
        :type wif: str.
        :return hex:
        :rtype: str.

        =============================================================================

        >>> WIF = "Your_Wif_Key" # example
        >>> hexed = self.Wif_To_Hex(WIF)

        =============================================================================

        """

        pvk = ''
        if wif[0] == '5':
            pvk = self.b58k1.b58_decode(wif)[2:-8]
        elif wif[0] in ['L', 'K']:
            pvk = self.b58k1.b58_decode(wif)[2:-10]
        else:
            raise ValueError("[Error] Incorrect WIF Key")
        return pvk

    # ==============================================================================
    def Wif_To_Decimal(self, wif):
        """

        Converts a WIF Key to Decimal


        :param wif:
        :type wif: str.
        :return deccimal:
        :rtype: int.

        =============================================================================

        >>> WIF = "Your_Wif_Key" # example
        >>> dec = self.Wif_To_Decimal(WIF)

        =============================================================================

        """
        pvk = ''
        pvk_hex = self.Wif_To_Hex(wif)
        if pvk_hex != '': pvk = int(pvk_hex, 16)
        return pvk

    # ==============================================================================
    def Hex_To_Wif(self, pvk: str, compress: bool = True) -> str:
        """
        Input Privatekey can in any 1 of these [Integer] [Hex] [Bytes] form

        :param pvk:
        :type pvk: str.
        :param compress:
        :type compress: bool.
        :return:
        :rtype: str.

        =============================================================================

        >>> pvk = "Your_Privatekey" # example
        >>> hexed = self.Hex_To_Wif(pvk)
        >>> uncompress_wif = self.Hex_To_Wif(pvk, False)
        >>> compress_wif = self.Hex_To_Wif(pvk, True)

        =============================================================================



        """
        inp = ''
        suff = '01' if compress else ''
        if type(pvk) in [int, str]:
            inp = bytes.fromhex('80' + fl(pvk) + suff)
        elif type(pvk) == bytes:
            stuf = bytes.fromhex(suff)
            inp = PREFIX_80 + fl(pvk) + stuf
        else:
            ValueError("[Error] Input Privatekey format [Integer] [Hex] [Bytes] allowed only")
        if inp != '':
            res = self.get_sha256(inp)
            res2 = self.get_sha256(res)
            return self.b58k1.b58_encode(inp + res2[:4])
        else:
            return inp

    # ==============================================================================
    @staticmethod
    def checksum(self, inp):
        """
        Checksum Algorithm Digest Double SHA256
        """
        res = get_sha256(get_sha256(inp))
        return res[:4]

    # ==============================================================================
    def Public_To_Addr(self, pub, addr_type, compress=True):
        res = Fuzz.pubkey_to_address(addr_type, compress, pub)
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return addr

    # ==============================================================================
    @staticmethod
    def Pub_To_RIPEMD160(self, pub: bytes, addr_type: int, compress: bool = True):

        """
        Converts a public key to RIPEMD160.

        public key for p2pkh: addr_type = 0
        ----------------------------------
        public key for p2sh: addr_type = 1
        ----------------------------------
        public key for bech32: addr_type = 2
        ----------------------------------

        :param pub:
        :param addr_type:
        :param compress:
        :return:

        """
        res = PREFIX_0 * 20
        Fuzz.pubkey_to_h160(addr_type, compress, pub, res)
        return res

    # ==============================================================================

    def Pub_To_RIPEMD160_DIGEST(self, pub: bytes, addr_type: int, compress: bool = True):
        res = self.Pub_To_RIPEMD160(pub, addr_type, compress)
        return self.byter(res)

    # ==============================================================================

    def Pub_To_Ethereum_Addr(self, pub: bytes):
        """ 65 Upub bytes input. Output is 20 bytes ETH address lowercase with 0x as hex string"""
        xy = pub[1:]
        res = Fuzz.pubkeyxy_to_ETH_address(xy)
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return '0x' + addr

    # ==============================================================================

    @staticmethod
    def Pub_To_Ethereum_Addr_Hash(self, xy):
        """
        65 Upub bytes input. Output is 20 bytes ETH address lowercase with 0x as hex string
        :param xy:
        :return:

        """

        res = PREFIX_0 * 20
        Fuzz.pubkeyxy_to_ETH_address_bytes(xy, res)
        return res

    # ==============================================================================

    def Pub_To_Ethereum_Addr_Digest(self, pub: bytes):
        """ 65 Upub bytes input. Output is 20 bytes ETH address lowercase without 0x"""
        xy = pub[1:]
        res = self.Pub_To_Ethereum_Addr(xy)
        return bytes(bytearray(res))

    # ==============================================================================

    @staticmethod
    def Load_To_Memory(self, input_bin: str, verbose: bool = False):
        """input_bin_file is sorted h160 data of 20 bytes each element.
        ETH address can also work without 0x if sorted binary format"""
        Fuzz.Load_data_to_memory(input_bin.encode("utf-8"), verbose)

    # ==============================================================================
    @staticmethod
    def Check_Collision(self, RIPEMD160):
        """ h160 is the 20 byte hash to check for collision in data, already loaded in RAM.
        Use the function Load_To_Memory before calling this check"""
        return Fuzz.check_collision(RIPEMD160)

    # ==============================================================================
    @staticmethod
    def Hex_To_Dec(self, hexed: str):
        return int(hexed, 16)

    # =============================================================================

    def Hex_To_Addr(self, hexed: str, compress: bool):
        dec = int(hexed, 16)
        if compress:
            return self.Decimal_To_Addr(dec, addr_type=0, compress=True)
        else:
            return self.Decimal_To_Addr(dec, addr_type=0, compress=False)

    # =============================================================================
    @staticmethod
    def Hex_To_Bytes(hexed: str) -> bytes:
        return bytes.fromhex(hexed)

    # =============================================================================

    @staticmethod
    def byter(mass):
        return bytes(bytearray(mass))

    # ==============================================================================
    @staticmethod
    def _ScalarMultiply(pvk: int):
        """ Integer value passed to function. 65 bytes uncompressed pubkey output """
        res = PREFIX_0 * 65
        pass_int_value = fl(pvk).encode('utf8')
        Fuzz.scalar_multiplication(pass_int_value, res)
        return res

    def ScalarMultiply(self, pvk: int):
        if pvk < 0: pvk = MAX_HEX + pvk
        res = self._ScalarMultiply(pvk)
        return self.byter(res)

    # ==============================================================================
    @staticmethod
    def _ScalarMultiplyList(self, pvklist):
        """
        Integer list passed to function. 65*len bytes uncompressed pubkey output. No Zero Point handling.
        """
        sz = len(pvklist)
        res = PREFIX_0 * (65 * sz)
        pvks = b''.join(pvklist)
        Fuzz.scalar_multiplications(pvks, sz, res)
        return res

    @staticmethod
    def ScalarMultiplyList(self, pvk_list):
        pvk_list = [bytes.fromhex(fl(MAX_HEX + i)) if i < 0 else bytes.fromhex(fl(i)) for i in pvk_list]
        res = self.ScalarMultiplyList(pvk_list)
        return self.byter(res)

    # ==============================================================================
    @staticmethod
    def _PointMultiplication(self, pubkey_bytes, kk):
        """ Input Point and Integer value passed to function. 65 bytes uncompressed pubkey output """
        res = PREFIX_0 * 65
        bytes_value = bytes.fromhex(hex(kk)[2:].zfill(64))  # strict 32 bytes scalar
        Fuzz.point_multiplication(pubkey_bytes, bytes_value, res)
        return res

    def PointMultiplication(self, P, k):
        if type(P) == int: k, P = P, k
        res = self.PointMultiplication(P, k)
        return self.byter(res)

    # ==============================================================================
    @staticmethod
    def _get_X_To_Y(self, x_hex, is_even):
        """ Input x_hex encoded as bytes and bool is_even. 32 bytes y of point output """
        res = PREFIX_0 * 32
        Fuzz.get_x_to_y(x_hex.encode('utf8'), is_even, res)
        return res

    @staticmethod
    def get_X_To_Y(self, x_hex, is_even):
        res = self._get_X_To_Y(x_hex, is_even)
        return self.byter(res)

    # ==============================================================================
    @staticmethod
    def _PointIncrement(self, pubkey_bytes):
        res = PREFIX_0 * 65
        Fuzz.point_increment(pubkey_bytes, res)
        return res

    @staticmethod
    def PointIncrement(self, pubkey_bytes):
        res = self._PointIncrement(pubkey_bytes)
        return self.byter(res)

    # ==============================================================================
    @staticmethod
    def _PointNegation(self, pubkey_bytes):
        res = PREFIX_0 * 65
        Fuzz.point_negation(pubkey_bytes, res)
        return res

    @staticmethod
    def PointNegation(self, pubkey_bytes):
        res = self._PointNegation(pubkey_bytes)
        return self.byter(res)

    # ==============================================================================

    @staticmethod
    def _PointDoubling(self, pubkey_bytes):
        res = PREFIX_0 * 65
        Fuzz.point_doubling(pubkey_bytes, res)
        return res

    def PointDoubling(self, pubkey_bytes):
        res = self._PointDoubling(pubkey_bytes)
        return self.byter(res)

    # ==============================================================================
    @staticmethod
    def init_P2_Group(self, pubkey_bytes):
        Fuzz.init_P2_Group(pubkey_bytes)

    # ==============================================================================

    @staticmethod
    def free_memory(self, pubkey_bytes):
        Fuzz.free_memory(pubkey_bytes)

    # ==============================================================================
    @staticmethod
    def _privatekey_to_h160(addr_type: int, compress: bool, pvk: int):
        if pvk < 0:
            pvk = MAX_HEX + pvk
        pass_int_value = fl(pvk).encode('utf8')
        res = PREFIX_0 * 32
        Fuzz.privatekey_to_h256(addr_type, compress, pass_int_value, res)
        return res

    def privatekey_to_h160(self, addr_type: int, compress: bool, pvk: int):
        res = self._privatekey_to_h160(addr_type, compress, pvk)
        return self.byter(res)

    # ==============================================================================
    def privatekey_to_address(self, addr_type: int, compress: bool, pvk: int):
        if pvk < 0:
            pvk = MAX_HEX + pvk
        pass_int_value = fl(pvk).encode('utf-8')
        if compress:
            res = Fuzz.privatekey_to_address(addr_type, True, pass_int_value)
        else:
            res = Fuzz.privatekey_to_address(addr_type, False, pass_int_value)
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return addr

    # ==============================================================================

    def hash160_to_address(self, addr_type: int, compress: bool, hash160_bytes: bytes):
        if compress:
            res = Fuzz.hash_to_address(addr_type, compress, hash160_bytes)
        else:
            res = Fuzz.hash_to_address(addr_type, True, hash160_bytes)
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return addr

    # ==============================================================================
    @staticmethod
    def _privatekey_loop_h160(num, addr_type: int, compress: bool, pvk: int):
        """ # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]"""
        if pvk < 0:
            pvk = MAX_HEX + pvk
        pass_int_value = fl(pvk).encode('utf8')
        res = PREFIX_0 * 32
        Fuzz.privatekey_loop_h160(num, addr_type, compress, pass_int_value, res)
        return res

    def privatekey_loop_h160(self, num, addr_type: int, compress: bool, pvk: int):
        if num <= 0: num = 1
        res = self._privatekey_loop_h160(num, addr_type, compress, pvk)
        return self.byter(res)

    # ==============================================================================
    def b58py(self, data):
        B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        if data[0] == 0:
            return "1" + self.b58py(data[1:])

        x = sum([v * (256 ** i) for i, v in enumerate(data[::-1])])
        ret = ""
        while x > 0:
            ret = B58[x % 58] + ret
            x = x // 58

        return ret

    # ==============================================================================
    def b58_encode(self, inp_bytes):
        res = Fuzz.b58_encode(inp_bytes, len(inp_bytes))
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return addr

    # ==============================================================================
    def b58_decode(self, inp):
        res = Fuzz.b58_decode(inp.encode("utf-8"))
        addr = self.fuzz256k1(res)
        Fuzz.free_memory(res)
        return addr

    # ==============================================================================

    def address_to_h160(self, addr: str) -> str:
        h160 = self.b58_decode(addr)
        return h160[2:-8]

    # ==============================================================================

    def btc_wif_to_pvk_hex(self, wif: str):
        pvk = ''
        if wif[0] == "5":
            pvk = self.b58_decode(wif)[2:-8]
        elif wif[0] in ['L', 'K']:
            pvk = self.b58_decode(wif)[2:-10]
        else:
            print("[Error] Incorrect WIF Key")
        return pvk

    # ==============================================================================

    def btc_wif_to_pvk_int(self, wif: str):
        pvk = ''
        pvk_hex = self.btc_wif_to_pvk_hex(wif)
        if pvk_hex != '':
            pvk = int(pvk_hex, 16)
        return pvk

    # ==============================================================================

    def btc_pvk_to_wif(self, pvk, compress: bool = True):
        inp = ''
        suff = '01' if compress else ''
        if type(pvk) in [int, str]:
            inp = bytes.fromhex('80' + fl(pvk) + suff)
        elif type(pvk) == bytes:
            inp = b'\x80' + fl(pvk) + bytes.fromhex(suff)
        else:
            print("[Error] Input Privatekey format [Integer] [Hex] [Bytes] allowed only")
        if pvk != '':
            comp = get_sha256(inp)
            comp2 = get_sha256(comp)
            return self.b58_encode(inp + comp2[:4])
        else:
            return inp
