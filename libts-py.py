import sys,ctypes,os

if sys.platform.startswith('linux'):
    libts = ctypes.CDLL(os.path.join(os.getcwd(), 'libts.so'))
elif sys.platform.startswith('win32'):
    libts = ctypes.CDLL(os.path.join(os.getcwd(), 'libts.dll'))
else:
    raise RuntimeError('Unsupported operating systems')

class ReturnCode(ctypes.c_int):
    Unknown = 0
    Verification_OK = 1
    Verification_FAIL = 2
    ERR_INVALID_PARAM = 3
    ERR_CANT_OPEN_FILE = 4
    ERR_CANT_CREATE_DATA = 5

class CA_TYPE(ctypes.c_int):
    CA_SYSTEM = 0
    CA_FILE = 1
    CA_PATH = 2
    CA_STORE = 3

libts.ts_verify_file.argtypes = [
    ctypes.c_char_p,  # data_file
    ctypes.c_char_p,  # sign_file
    CA_TYPE,          # ca_type
    ctypes.c_char_p   # ca
]
libts.ts_verify_file.restype = ReturnCode

def ts_verify_file(data_file:str, sign_file:str, ca_type:CA_TYPE = CA_TYPE.CA_SYSTEM, ca:str = "") -> bool:
    result = libts.ts_verify_file(ctypes.c_char_p(bytes(data_file, 'utf-8')), ctypes.c_char_p(bytes(sign_file, 'utf-8')), ca_type, ctypes.c_char_p(bytes(ca, 'utf-8')))
    return result.value == 1

print(ts_verify_file("test.txt", "test.txt.tsr"))
