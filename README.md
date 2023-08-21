
# セキュリティ・ミニキャンプ新潟 -- 資料

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
```
openssl version
python --version
pip list 2>/dev/null | grep pyscard
```
