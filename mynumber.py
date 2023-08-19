# マイナンバーカード操作用プログラム
#
# 使い方：
#   (1)./secrets.confにマイナンバーカードの認証情報（PIN）を記載してください。
#
#   [secrets]
#   password1=4桁の数字
#   password2=6桁以上の英数字
#
#   (2)カードリーダをUSBで接続した上でプログラムmynumber.pyを実行してください。
#

import io
import hashlib
import configparser
from smartcard.System import readers as get_readers  # pip install pyscard

import mynumber_apdu
from mynumber_oid import OID


def hexlist2int(hexlist):
    res = hexlist[0]
    for value in hexlist[1:]:
        res <<= 8
        res += value
    return res

def hexlist2str(hexlist):
    return " ".join("%02x" % x for x in hexlist)


class Cert:
    """証明書の種類"""
    AUTH = 1  # 認証用
    SIGN = 2  # 署名用


class APDUSelectCmd:
    # JLIS-AP
    CERT_AP     = [0x00, 0xA4, 0x04, 0x0C, 0x0A, 0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01]

    SIGN_CERT   = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x01]
    SIGNCA_CERT = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x02]
    SIGN_KEY    = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x1A]
    SIGN_PIN    = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x1B]

    AUTH_CERT   = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x0A]
    AUTHCA_CERT = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x0B]
    AUTH_KEY    = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x17]
    AUTH_PIN    = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x18]

    # 券面入力補助AP
    INFO_AP     = [0x00, 0xA4, 0x04, 0x0C, 0x0A, 0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08]

    INFO_PIN    = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x11]
    INFO_MYNUM  = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x01]
    INFO_MYDATA = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x02]


class JPKICardReader:

    def __init__(self):
        # カードリーダの一覧取得
        self.readers = get_readers()

    def connect(self, index: int=0):
        """一覧から指定した番号のカードリーダに接続"""
        self.conn = self.readers[index].createConnection()
        self.conn.connect()

    def sendAPDU(self, send_data: list[int]) -> (list[int], int, int):
        """マイナンバーカードと通信をする"""
        assert all(0 <= ch < 256 for ch in send_data)
        print('> %s' % hexlist2str(send_data))
        recv_data, sw1, sw2 = self.conn.transmit(send_data)
        print('< ', end='')
        if len(recv_data) > 0:
            print('%s ' % hexlist2str(recv_data), end='')
        print('%02x %02x' % (sw1, sw2))
        return recv_data, sw1, sw2


    def get_cert(self, cert_type: Cert, outputfile: str, password: str=None) -> (bool, str):
        """認証用・署名用証明書の取得"""

        print('[*] 公的個人認証AP(DF)')
        data, sw1, sw2 = self.sendAPDU(APDUSelectCmd.CERT_AP)

        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        if cert_type == Cert.SIGN:
            print('[*] 公的個人認証AP(DF) > 署名用PIN(EF)')
            data, sw1, sw2 = self.sendAPDU(APDUSelectCmd.SIGN_PIN)
            if not mynumber_apdu.is_success(sw1, sw2):
                return False, mynumber_apdu.show_error(sw1, sw2)

            print('[*] PINロックの解除')
            if password is None:
                return False, 'PINロック解除用のパスワードを入力してください!!'
            password_hexlist = [ord(ch) for ch in password]
            password_length = len(password_hexlist)
            send = [0x00, 0x20, 0x00, 0x80, password_length] + password_hexlist
            data, sw1, sw2 = self.sendAPDU(send)
            if not mynumber_apdu.is_success(sw1, sw2):
                return False, mynumber_apdu.show_error(sw1, sw2)

        if cert_type == Cert.AUTH:
            print('[*] 公的個人認証AP(DF) > 認証用証明書FILE(EF)')
            send = APDUSelectCmd.AUTH_CERT
        elif cert_type == Cert.SIGN:
            print('[*] 公的個人認証AP(DF) > 署名用証明書FILE(EF)')
            send = APDUSelectCmd.SIGN_CERT

        data, sw1, sw2 = self.sendAPDU(send)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] 証明書FILEの読み取り')
        cert_data = []
        data, sw1, sw2 = self.sendAPDU([0x00, 0xB0, 0x00, 0x00, 0x04])
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)
        cert_data += data

        if cert_data[0] != 0x30:
            return False, '読み取りデータは証明書ではないです!!'

        # 証明書の長さ
        if (cert_data[1] >> 7) == 0:
            # TLVのLengthの最上位bitが0のとき、データは127byteより小さい
            cert_length_length = 1
            cert_length = cert_data[1]
        else:
            # TLVのLengthの最上位bitが1のとき、データは128byte以上
            cert_length_length = int(cert_data[1] & 0x7f)
            cert_length = hexlist2int(cert_data[2:2+cert_length_length])
        print('[*] 証明書の長さフィールドのバイト長 :', cert_length_length)
        print('[*] 証明書の長さ :', cert_length)

        der_length = 2 + cert_length_length + cert_length
        der_length = cert_length
        upper = (der_length >> 8) & 0xFF
        lower = (der_length     ) & 0xFF
        data, sw1, sw2 = self.sendAPDU([0x00, 0xB0, 0x00, 0x04, 0x00, upper, lower])
        cert_data += data

        with open(outputfile, 'wb') as f:
            f.write(bytearray(cert_data))

        print('[+] 証明書を出力しました : %s' % outputfile)
        return True, outputfile


    def sign(self, cert_type: Cert, password: str, target_filepath: str) -> (bool, str):
        """認証用・署名用秘密鍵による署名"""

        print('[*] 公的個人認証AP(DF)')
        data, sw1, sw2 = self.sendAPDU(APDUSelectCmd.CERT_AP)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        if cert_type == Cert.AUTH:
            print('[*] 公的個人認証AP(DF) > 認証用PIN(EF)')
            send = APDUSelectCmd.AUTH_PIN
        elif cert_type == Cert.SIGN:
            print('[*] 公的個人認証AP(DF) > 署名用PIN(EF)')
            send = APDUSelectCmd.SIGN_PIN
        data, sw1, sw2 = self.sendAPDU(send)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] PINロックの解除')
        password_hexlist = [ord(ch) for ch in password]
        password_length = len(password_hexlist)
        send = [0x00, 0x20, 0x00, 0x80, password_length] + password_hexlist
        data, sw1, sw2 = self.sendAPDU(send)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        if cert_type == 1:
            print('[*] 公的個人認証AP(DF) > 認証用秘密鍵FILE(EF)')
            send = APDUSelectCmd.AUTH_KEY
        elif cert_type == 2:
            print('[*] 公的個人認証AP(DF) > 署名用秘密鍵FILE(EF)')
            send = APDUSelectCmd.SIGN_KEY
        data, sw1, sw2 = self.sendAPDU(send)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] 署名情報')
        oid_data = [int(x) for x in OID.str2byte('2.16.840.1.101.3.4.2.1')]  # SHA256
        oid = [0x06, len(oid_data)] + oid_data
        null = [0x05, 0x00]
        sequence = [0x30, len(oid)+len(null)] + oid + null

        hashalg = hashlib.sha256()
        with open(target_filepath, 'rb') as f:
            hashalg.update(f.read())
        digest = list(bytearray(hashalg.digest()))
        octet_string = [0x04, len(digest)] + digest

        digestinfo = [0x30, len(sequence)+len(octet_string)] + sequence + octet_string
        print(hexlist2str(digestinfo))

        # COMPUTE DIGITAL SIGNATURE
        send = [0x80, 0x2A, 0x00, 0x80, len(digestinfo)] + digestinfo + [0x00]
        data, sw1, sw2 = self.sendAPDU(list(send))
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)
        print('[*] 署名結果')
        print(hexlist2str(data))

        sig_file = target_filepath + '.sig'
        with open(sig_file, 'wb') as f:
            f.write(bytearray(data))

        print('[+] 署名ファイルを出力しました : %s' % sig_file)
        return True, sig_file


    def get_mynumber(self, password: str) -> (bool, str):
        """個人番号の取得"""

        print('[*] 券面AP(DF)')
        data, sw1, sw2 = self.sendAPDU(APDUSelectCmd.INFO_AP)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] 券面AP(DF) > 認証用PIN(EF)')
        send = APDUSelectCmd.INFO_PIN
        data, sw1, sw2 = self.sendAPDU(send)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] PINロックの解除')
        password_hexlist = [ord(ch) for ch in password]
        password_length = len(password_hexlist)
        send = [0x00, 0x20, 0x00, 0x80, password_length] + password_hexlist
        data, sw1, sw2 = self.sendAPDU(send)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] 券面AP(DF) > マイナンバー(EF)')
        send = APDUSelectCmd.INFO_MYNUM
        data, sw1, sw2 = self.sendAPDU(send)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] マイナンバー読み取り')
        data, sw1, sw2 = self.sendAPDU([0x00, 0xB0, 0x00, 0x00, 0x00])
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print(hexlist2str(data))
        mynumber_str = ''.join(chr(ch) for ch in data[3:3+12])
        print(mynumber_str)

        return True, mynumber_str


    def get_personal_data(self, password: str) -> (bool, str):
        """券面情報読み取り"""

        print('[*] 券面AP(DF)')
        data, sw1, sw2 = self.sendAPDU(APDUSelectCmd.INFO_AP)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] 券面AP(DF) > 認証用PIN(EF)')
        send = APDUSelectCmd.INFO_PIN
        data, sw1, sw2 = self.sendAPDU(send)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] PINロックの解除')
        password_hexlist = [ord(ch) for ch in password]
        password_length = len(password_hexlist)
        send = [0x00, 0x20, 0x00, 0x80, password_length] + password_hexlist
        data, sw1, sw2 = self.sendAPDU(send)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] 券面AP(DF) > 基本4情報(EF)')
        send = APDUSelectCmd.INFO_MYDATA
        data, sw1, sw2 = self.sendAPDU(send)
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        print('[*] 基本4情報の読み取り')
        data, sw1, sw2 = self.sendAPDU([0x00, 0xB0, 0x00, 0x02, 0x01])
        if not mynumber_apdu.is_success(sw1, sw2):
            return False, mynumber_apdu.show_error(sw1, sw2)

        data_len = data[0] + 3
        print('[*] 長さ :', hex(data_len))

        upper = (data_len >> 8) & 0xFF
        lower = (data_len     ) & 0xFF
        data, sw1, sw2 = self.sendAPDU([0x00, 0xB0, 0x00, 0x00, data_len])

        bytedata = io.BytesIO(bytearray(data))

        # ヘッダー
        tmp = bytedata.read(3)
        content_len = tmp[2]

        # 不明データを読み飛ばす
        tmp = bytedata.read(3)
        unknown_len = tmp[2]
        unknown = bytedata.read(unknown_len)

        # 氏名の取得
        tmp = bytedata.read(3)
        name_len = tmp[2]
        name = bytedata.read(name_len)
        name = name.decode('utf-8')
        print('[+] 氏名 :', name)

        # 住所の取得
        tmp = bytedata.read(3)
        address_len = tmp[2]
        address = bytedata.read(address_len)
        address = address.decode('utf-8')
        print('[+] 住所 :', address)

        # 生年月日の取得
        tmp = bytedata.read(3)
        birthday_len = tmp[2]
        birthday = bytedata.read(birthday_len)
        birthday = birthday.decode()
        print('[+] 生年月日' + birthday)

        # 性別の取得
        tmp = bytedata.read(3)
        sex_len = tmp[2]
        sex = bytedata.read(sex_len)
        sex_str = sex.decode()
        sex_desc = ""
        if sex_str == '1':
            sex_desc = '男性'
        elif sex_str == '2':
            sex_desc = '女性'
        elif sex_str == '9':
            sex_desc = '適用不能'
        else:
            sex_desc = '不明'
        print('[+] 性別', sex_desc)

        return True, [name, address, birthday, sex_desc]


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('secrets.conf')
    password1 = config['secrets']['password1']
    password2 = config['secrets']['password2']

    cardreader = JPKICardReader()
    cardreader.connect()

    # res, text = cardreader.get_cert(Cert.AUTH, outputfile="認証用証明書.der")
    # res, text = cardreader.get_cert(Cert.SIGN, outputfile="署名用証明書.der", password=password2)
    # res, text = cardreader.sign(Cert.AUTH, password=password1, target_filepath='重要書類.txt')
    res, text = cardreader.sign(Cert.SIGN, password=password2, target_filepath='重要書類.txt')
    # res, text = cardreader.get_mynumber(password=password1)
    # res, text = cardreader.get_personal_data(password=password1)
