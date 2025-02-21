import sys, ctypes, os
from datetime import datetime, timedelta

class libts_ReturnCode(ctypes.c_int):
    UNDEFINED = 0
    VERIFICATION_OK = 1
    VERIFICATION_FAIL = 2
    INVALID_PARAM = 3
    OPENSSL_ERROR = 4

class libts_CA_TYPE(ctypes.c_int):
    CA_SYSTEM = 0
    CA_FILE = 1
    CA_PATH = 2
    CA_STORE = 3

class libts_caller:
    def __init__(self):
        self.loaded = False

    def load_dll(self):
        if not self.loaded:
            if sys.platform.startswith('linux'):
                self.libts = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libts.so'))
            elif sys.platform.startswith('win32'):
                self.libts = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libts.dll'))
            else:
                raise RuntimeError('Unsupported operating systems')
            
            self.libts.ts_verify_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_bool]
            self.libts.ts_verify_file.restype = ctypes.c_int

            self.libts.ts_get_last_openssl_error.argtypes = []
            self.libts.ts_get_last_openssl_error.restype = ctypes.c_char_p

            self.libts.resp_get_signing_time.argtypes = []
            self.libts.resp_get_signing_time.restype = ctypes.c_uint64

            self.loaded = True

    def verify_file(self, data_file:str, sign_file:str, parse_resp = True, ca_type:int = libts_CA_TYPE.CA_SYSTEM, ca:str = "") -> int:
        self.load_dll()
        return self.libts.ts_verify_file(ctypes.c_char_p(bytes(data_file, 'utf-8')), ctypes.c_char_p(bytes(sign_file, 'utf-8')), ca_type, ctypes.c_char_p(bytes(ca, 'utf-8')), parse_resp)

    def get_sign_time(self) -> int:
        self.load_dll()
        return self.libts.resp_get_signing_time()

    def get_error_msg(self, code: int) -> str:
        self.load_dll()
        if code == libts_ReturnCode.UNDEFINED:
            return "程序出现了未定义行为（笑"
        if code == libts_ReturnCode.VERIFICATION_OK:
            return "验证成功"
        if code == libts_ReturnCode.VERIFICATION_FAIL:
            return f"验证失败 {self.libts.ts_get_last_openssl_error().decode('utf-8')}"
        if code == libts_ReturnCode.INVALID_PARAM:
            return "参数错误"
        if code == libts_ReturnCode.OPENSSL_ERROR:
            return self.libts.ts_get_last_openssl_error().decode('utf-8')

libts = libts_caller()

print(libts.get_error_msg(libts.verify_file("test.txt", "test.txt.tsr")))

utc_time  = datetime.fromtimestamp(libts.get_sign_time())
print(f"UTC时间：{utc_time}")
print(f"北京时间：{utc_time + timedelta(hours=8)}")
