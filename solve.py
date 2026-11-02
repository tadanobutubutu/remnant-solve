#!/usr/bin/env python3
"""Remnant (Daily AlpacaHack) の解法スクリプト。

サーバーはフラグを Base64 エンコードした文字列（以下 secret）を保持し、
送った入力 x に対して b64decode(secret XOR x) を試す。
デコードで例外が出ると "Error..."、成功すると "Incorrect..."、
x が secret と完全一致すると "Correct!" が返る。

Python の b64decode は（デフォルトでは）Base64 アルファベット以外の
バイトを無視するが、残ったデータ文字がちょうど 1 個だと長さ不正で
例外になる。この「例外になるかどうか」を 1 ビットのオラクルとして使い、
secret を 1 バイトずつ特定する。

使い方:
    python3 solve.py <HOST> <PORT>
"""

import base64
import re
import socket
import sys

# Base64 のデータ文字 64 種と、末尾パディングの '=' を合わせた 65 通りが
# secret の各バイトの候補になる（b64encode の出力はこの範囲しか取らない）。
ALPHABET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
CANDIDATES = sorted(ALPHABET | {ord("=")})

# プローブとして送るバイト値。改行 (LF) と復帰 (CR) は、サーバーが
# input() で 1 行ずつ読む都合上、入力の一部として送れないため除く。
# 残りの 126 通りでも、候補 65 通りの署名はすべて相異なる（下で検証）。
PROBES = [value for value in range(128) if value not in (10, 13)]

# サーバーの応答 3 種にマッチするパターン。
STATUS_RE = re.compile(rb"(Error\.\.\.|Incorrect\.\.\.|Correct!)\r?\n")

# 探索するエンコード済み文字列の最大長（バイト）。
MAX_LENGTH = 128


def build_signature_table():
    """候補バイトごとに「オラクルの応答パターン（署名）」を事前計算する。

    候補 c に対して、プローブ p を送ったときに Error になるのは
    c XOR p が Base64 アルファベットに含まれるとき、そのときに限る。
    全プローブに対する Error / 非 Error の並びが候補ごとに異なるため、
    実測した並びから候補を一意に逆引きできる。
    """
    table = {}
    for candidate in CANDIDATES:
        signature = tuple((candidate ^ probe) in ALPHABET for probe in PROBES)
        if signature in table:
            raise RuntimeError("候補の署名が重複しています")
        table[signature] = candidate
    return table


def connect(host, port):
    """サーバーに接続し、最初の "Input: " プロンプトまで読み進める。"""
    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(15)
    prompt = bytearray()
    while b"Input: " not in prompt:
        chunk = sock.recv(4096)
        if not chunk:
            sock.close()
            raise RuntimeError("プロンプトが来る前に接続が切れました")
        prompt.extend(chunk)
    return sock


def read_statuses(sock, count):
    """サーバーの応答を count 件分だけ読み取って返す。"""
    data = bytearray()
    while True:
        statuses = STATUS_RE.findall(bytes(data))
        if len(statuses) >= count:
            return statuses[:count]
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("応答を読み切る前に接続が切れました")
        data.extend(chunk)


def recover_secret(sock, table):
    """オラクルを繰り返し使って secret を 1 バイトずつ復元する。"""
    recovered = bytearray()
    for index in range(MAX_LENGTH):
        prefix = bytes(recovered)
        # 既知の接頭辞にプローブを 1 バイト付けた行を、全プローブ分まとめて送る。
        # 接頭辞の部分は secret と同じ値なので XOR が 0 になり、
        # NUL バイトはデコーダに無視される。実質的に残るのは末尾 1 バイトだけ。
        batch = b"".join(prefix + bytes([probe]) + b"\n" for probe in PROBES)
        sock.sendall(batch)
        statuses = read_statuses(sock, len(PROBES))

        observed = tuple(status == b"Error..." for status in statuses)

        # 末尾に何を付けても Error にならない位置は、secret の終端を意味する。
        # zip(secret, x) が secret の長さで切り捨てられ、XOR がすべて 0 になるため。
        if not any(observed):
            print(f"encoded length: {index}")
            return bytes(recovered)

        candidate = table.get(observed)
        if candidate is None:
            raise RuntimeError(f"位置 {index} に対応する候補がありません")
        recovered.append(candidate)
        print(f"byte {index}: {chr(candidate)!r}")
    raise RuntimeError(f"secret が {MAX_LENGTH} バイト以内に収まりませんでした")


def main():
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <HOST> <PORT>", file=sys.stderr)
        return 1
    host, port = sys.argv[1], int(sys.argv[2])

    table = build_signature_table()

    sock = connect(host, port)
    try:
        encoded = recover_secret(sock, table)

        # 復元した Base64 文字列をデコードし、フラグ形式を確認する。
        flag = base64.b64decode(encoded, validate=True)
        print(f"recovered base64: {encoded.decode('ascii')}")
        if not (flag.startswith(b"Alpaca{") and flag.endswith(b"}")):
            raise RuntimeError("デコード結果が想定するフラグ形式と異なります")

        # 復元した文字列そのものを送り、"Correct!" が返るか同じ接続で確認する。
        sock.sendall(encoded + b"\n")
        verdict = read_statuses(sock, 1)[0]
        print(f"verification (same connection): {verdict.decode()}")
        if verdict != b"Correct!":
            raise RuntimeError("検証に失敗しました")
    finally:
        sock.close()

    # 新しい接続でもう一度確認する。
    fresh = connect(host, port)
    try:
        fresh.sendall(encoded + b"\n")
        verdict = read_statuses(fresh, 1)[0]
        print(f"verification (fresh connection): {verdict.decode()}")
        if verdict != b"Correct!":
            raise RuntimeError("再接続での検証に失敗しました")
    finally:
        fresh.close()

    print(f"Flag: {flag.decode('ascii')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
