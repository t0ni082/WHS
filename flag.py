import re

with open("pid.708.dmp", "rb") as f:
    data = f.read()

pattern = re.compile(b"\x64.{6,8}\x40\x06.{18}\x5a\x0c\x00\x00")

count = 1
for match in pattern.finditer(data):
    sig_end = match.end()
    after_sig = data[sig_end:sig_end + 32]

    try:
        text = after_sig.decode("ascii", errors="ignore")
        print(f"({count}) After Signature: {text.strip()}")
        count += 1
    except Exception:
        continue
