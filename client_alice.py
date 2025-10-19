from .client_common import *
from .x3dh import sender_x3dh, safety_fingerprint, b64d
from olm import Account, Session

DEVICE = "alice"

def start_session_and_send(text: str):
    bresp = post("/bundle/fetch", {"user_id": "bob"})
    bob_ik_pub = b64d(bresp["ik_dh_pub_b64"])
    fp = safety_fingerprint(bob_ik_pub)
    log(DEVICE, f"Bob safety fingerprint (share OOB): {fp}")

    from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
    from .x3dh import gen_identity
    ident = gen_identity("alice")
    secret, ek_pub = sender_x3dh(
        ident,
        bob_ik_dh_pub=b64d(bresp["ik_dh_pub_b64"]),
        bob_ik_sig_pub=b64d(bresp["ik_sig_pub_b64"]),
        bob_spk_pub=b64d(bresp["spk_pub_b64"]),
        bob_spk_signature=b64d(bresp["spk_signature_b64"]),
        bob_opk_pub=b64d(bresp["opk_pub_b64"]) if bresp["opk_pub_b64"] else None,
    )
    log(DEVICE, f"Derived SK digest: {safety_fingerprint(secret.sk)}")

    oresp = post("/olm/fetch", {"user_id": "bob"})
    if not oresp.get("id_key"): raise SystemExit("Bob has not published Olm keys.")
    bob_idkey = oresp["id_key"]
    bob_otk = oresp["one_time_key"]
    acc = Account()
    sess = Session()
    sess.create_outbound(acc, bob_idkey, bob_otk)

    prekey_msg = sess.encrypt("init-from-alice")
    post("/msg/send", {"to": "bob", "sender": "alice", "body": prekey_msg})
    log(DEVICE, "Sent prekey message.")

    c = sess.encrypt(text)
    post("/msg/send", {"to": "bob", "sender": "alice", "body": c})
    log(DEVICE, f"Sent ciphertext: {c}")

    save_json(DEVICE, "olm_state", {"pickle": acc.pickle("alice-passphrase")})
    save_json(DEVICE, "session_outbound", {"pickle": sess.pickle("alice-passphrase")})

def send(text: str):
    st = load_json(DEVICE, "session_outbound")
    if not st: raise SystemExit("No outbound session. Run start first.")
    acc = Account.from_pickle(load_json(DEVICE, "olm_state")["pickle"], "alice-passphrase")
    sess = Session.from_pickle(st["pickle"], "alice-passphrase")
    c = sess.encrypt(text)
    post("/msg/send", {"to": "bob", "sender": "alice", "body": c})
    log(DEVICE, f"Sent ciphertext: {c}")

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["start", "send"])
    ap.add_argument("--text", default="Hello from Alice")
    args = ap.parse_args()
    if args.cmd == "start": start_session_and_send(args.text)
    elif args.cmd == "send": send(args.text)
