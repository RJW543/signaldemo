from .client_common import *
import json

def peek(to="bob"):
    q = get("/msg/peek", {"user_id": to})["queue"]
    print(json.dumps(q, indent=2))
    return q

def tamper(to="bob"):
    q = peek(to)
    if not q: 
        print("No messages to tamper."); return
    m = q[-1]  
    body = m["body"]
    ct = body.get("ciphertext", "")
    if not ct:
        print("Not an Olm message?"); return
    b = bytearray(ct.encode())
    if b:
        b[0] = (b[0] ^ 1) % 255
    body_tampered = {"type": body["type"], "ciphertext": bytes(b).decode(errors="ignore")}
    post("/msg/append", {"to": to, "sender": "attacker", "body": body_tampered})
    print("Tampered message appended.")

def replay(to="bob"):
    q = peek(to)
    if not q:
        print("No messages to replay."); return
    m = q[0]  
    post("/msg/append", {"to": to, "sender": "attacker", "body": m["body"]})
    print("Replayed message appended.")

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["peek", "tamper", "replay"])
    ap.add_argument("--to", default="bob")
    args = ap.parse_args()
    if args.cmd == "peek": peek(args.to)
    elif args.cmd == "tamper": tamper(args.to)
    elif args.cmd == "replay": replay(args.to)
