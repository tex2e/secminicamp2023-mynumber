
# セキュリティ・ミニキャンプ新潟 -- 資料

### スライド

- [マイナンバーカードの暗号技術とセキュリティ - Speaker Deck](https://speakerdeck.com/tex2e/secminicamp2023-mynumber)

### 事前準備

1. opensslコマンドのインストール
    - Windowsの場合は、Git Bashでも可
    - MacOSの場合は、`brew install openssl` を実行
3. pythonの最新版をインストール
    - Windowsの場合は、Python for Windows のインストーラーを実行
    - MacOSの場合は、`brew install python` を実行
4. pipでライブラリpyscardをインストール
    ```
    pip install pyscard
    ```

### 確認

以下のコマンドを実行して、それぞれでバージョンが表示されれば事前準備完了です！

Windowsの場合：
```
openssl version
py --version
py -m pip list | sls pyscard
```
MacOSの場合：
```
openssl version
python --version
pip list | grep pyscard
```

### 注意事項

- NFCリーダーは PaSoRi RC-S300 でのみ動作確認済みです。
- Windows Subsystem for Linux (WSL) だと、デフォルトではUSBデバイスを認識できないため、Windows上に環境構築をお願いします。
