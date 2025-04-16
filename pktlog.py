import frida
import sys
import json
import bson

# 실행 중인 카톡에 접근
session = frida.attach("KakaoTalk.exe")

def on_message(message, data):
    if message["type"] == "send":
        payload = json.loads(message["payload"])
        packet = bytes(payload)

        # BSON 헤더에서 전체 길이 추출
        bson_len = int.from_bytes(packet[:4], byteorder='little')
        bson_part = packet[:bson_len]
        rest = packet[bson_len:]

        # 시도 1: BSON 파싱
        try:
            doc = bson.loads(bson_part)
            print("Parsed BSON:")
            for k, v in doc.items():
                print(f"  {k}: {v}")
        except Exception as e:
            print("BSON 파싱 실패:", e)

        # 시도 2: 나머지를 UTF-16LE로 해석
        try:
            decoded = rest.decode('utf-16le', errors='ignore')
            print("UTF-16LE 디코딩 결과:")
            print(decoded)
        except Exception as e:
            print("UTF-16 디코딩 실패:", e)

        print("=" * 60)
    else:
        print(message)

# dynamic.js 또는 hook.js 사용 가능
script = session.create_script(open("dynamic.js", encoding="utf-8").read())
script.on("message", on_message)
script.load()

session.resume()
input("[*] Press Enter to quit...\n")

import frida
import sys
import json
import bson
