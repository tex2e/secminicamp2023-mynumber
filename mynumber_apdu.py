# APDUステータスの詳細情報取得

# Complete list of APDU responses - EFTLab - Breakthrough Payment Technologies
# https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/
def get_status_msg(sw1, sw2):
    if sw1 == 0x90 and sw2 == 0x00:
        return "I: 正常終了"
    if sw1 == 0x61:
        return f"I: 出力成功。残り{int(sw2)}バイトが出力可能です。"
    if sw1 == 0x62:
        if sw2 == 0x81: return "W: 出力データに異常があります。"
        if sw2 == 0x83: return "W: 選択したファイルは無効になりました。"
        return "W: 不揮発性メモリの状態は変更されていません。"
    if sw1 == 0x63:
        if sw2 == 0x81: return "W: ファイルの書き込み可能領域が不足しています。"
        if (sw2 >> 4) == 0xc: return f"W: 検証失敗。残り{int(sw2 & 0x0f)}回リトライ可能です。"
        return "W: 不揮発性メモリの状態は変化しています。"
    if sw1 == 0x64:
        if sw2 == 0x01: return "E: コマンドはタイムアウトしました。"
        return "E: 不揮発性メモリの状態は変更されていません。"
    if sw1 == 0x65:
        if sw2 == 0x01: return "E: 書き込みエラーが発生しました。"
        return "E: 不揮発性メモリの状態は変化しています。"
    if sw1 == 0x66:
        if sw2 == 0x00: return "E: 受信時にタイムアウトエラーが発生しました。"
        if sw2 == 0x01: return "E: 受信時にパリティチェックエラーが発生しました。"
        if sw2 == 0x02: return "E: 受信時にチェックサムエラーが発生しました。"
        if sw2 == 0x69: return "E: 不正な暗号化/復号パディングが含まれています。"
        return "E: セキュリティエラーが発生しました。"
    if sw1 == 0x67:
        if sw2 == 0x00: return "E: データ長 (Lc/Leフィールド) が不正です。"
        return "E: データ長が不正です。"
    if sw1 == 0x68:
        return "E: CLAの機能は対応していません。"
    if sw1 == 0x69:
        if sw2 == 0x81: return "E: ファイル構造と互換性のないコマンドです。"
        if sw2 == 0x82: return "E: セキュリティ条件が満たされていません。"
        if sw2 == 0x83: return "E: 認証方法がブロックされています。"
        if sw2 == 0x84: return "E: 参照データがブロックされました。"
        if sw2 == 0x85: return "E: コマンドの使用条件を満たしていません。"
        if sw2 == 0x86: return "E: ファイルが存在しません。"
        if sw2 == 0x87: return "E: セキュアメッセージングに必要なデータオブジェクトが存在しません。"
        if sw2 == 0x88: return "E: セキュアメッセージングのデータオブジェクトが不正です。"
        return "E: コマンドは許可されていません。"
    if sw1 == 0x6a:
        if sw2 == 0x80: return "E: データフィールドのパラメータが正しくないです。"
        if sw2 == 0x81: return "E: サポートされていない機能です。"
        if sw2 == 0x82: return "E: ファイルが存在しません。"
        if sw2 == 0x83: return "E: レコードが存在しません。"
        if sw2 == 0x84: return "E: レコードまたはファイルのメモリ容量が不足しています。"
        if sw2 == 0x85: return "E: LcはTLV構造と一致しません。"
        if sw2 == 0x86: return "E: P1またはP2パラメータが正しくありません。"
        if sw2 == 0x87: return "E: LcがP1-P2と一致しない。"
        if sw2 == 0x88: return "E: 参照データが見つかりません。"
        if sw2 == 0x89: return "E: ファイルが既に存在します。"
        if sw2 == 0x8A: return "E: DF名が既に存在します。"
        return "E: パラメータの値が間違っています。"
    if sw1 == 0x6b:
        return "E: パラメータの値が間違っています。"
    if sw1 == 0x6d:
        return "E: 命令コード(INS)が不正です。"
    if sw1 == 0x6e:
        return "E: 命令クラス(CLA)が不正です。"
    if sw1 == 0x6f:
        return "E: 内部エラーが発生しました。"
    return ""

def is_success(sw1, sw2):
    return ((sw1 == 0x90 and sw2 == 0x00) or (sw1 == 0x61))

def show_error(sw1, sw2):
    print("%x %x: %s" % (sw1, sw2, get_status_msg(sw1, sw2)))
