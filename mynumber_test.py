# マイナンバーカード情報読み取りプログラムの動作確認用テスト
# 注意：
#   正しくないパスワードを設定すると、不正なログインをテストで複数回実施することで
#   マイナンバーカードへのアクセスがロックされてしまいます。
#   実行する前にsecrets.confの内容が正しいか確認ください。

import unittest
import configparser

from mynumber import *


class TestJPKIReader(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        config = configparser.ConfigParser()
        config.read('secrets.ini')
        cls.password1 = config['secrets']['password1']
        cls.password2 = config['secrets']['password2']

        cls.cardreader = JPKICardReader()
        cls.cardreader.connect(0)

    def test_get_cert_auth(self):
        res, text = self.__class__.cardreader.get_cert(Cert.AUTH, '認証用証明書.der')
        self.assertTrue(res)

    def test_get_cert_sign(self):
        res, text = self.__class__.cardreader.get_cert(Cert.SIGN, '署名用証明書.der', password=self.__class__.password2)
        self.assertTrue(res)

    def test_sign_auth(self):
        res, text = self.__class__.cardreader.sign(Cert.AUTH, password=self.__class__.password1, target_filepath='重要書類.txt')
        self.assertTrue(res)

    def test_sign_auth(self):
        res, text = self.__class__.cardreader.sign(Cert.SIGN, password=self.__class__.password2, target_filepath='重要書類.txt')
        self.assertTrue(res)

    def test_get_mynumber(self):
        res, text = self.__class__.cardreader.get_mynumber(password=self.__class__.password1)
        self.assertTrue(res)

    def test_get_personal_data(self):
        res, text = self.__class__.cardreader.get_personal_data(password=self.__class__.password1)
        self.assertTrue(res)


if __name__ == '__main__':
    unittest.main()
