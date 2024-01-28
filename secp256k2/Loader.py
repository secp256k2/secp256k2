# Python Secp256k1 Library
import sys, os, ctypes


def load_dynamic_lib(lib_path):
    if not os.path.isfile(lib_path):
        raise ValueError(f"File {lib_path} not found")
    try:
        lib = ctypes.CDLL(lib_path)
    except Exception as e:
        raise ValueError(f"Error loading {lib_path}: {e}")
    return lib


def Load_cPack():
    dirPath = os.path.dirname(os.path.realpath(__file__))
    if 'win' in sys.platform.lower():
        secFile = dirPath + '\\_secp256k2.dll'
    elif sys.platform.lower() in ['linux']:
        secFile = dirPath + '/_secp256k2.so'
    else:
        raise EnvironmentError("Unsupported platform")
    return load_dynamic_lib(secFile)
