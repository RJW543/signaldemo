from .client_common import *
from .x3dh import gen_identity, gen_client_state, safety_fingerprint
from olm import Account, Session

DEVICE = "bob"

def register():
    from .x3dh import b64
    ident = gen_identity("bob")
    state = gen_client_state(ident, num_opks=10)

    bundle = {
        "user_id": "bob",
        "ik_dh_pub_b64": b64(state.identity.ik_dh_pub),
        "ik_sig_pub_b64": b64(state.identity.ik_sig_pub),
        "spk_pub_b64": b64(state.spk_pub),
        "spk_signature_b64": b64(state.spk_signature),
        "opk_pubs_b64": [b64(p) for p in state.opk_pubs],
    }
    post("/bundle/upload", bundle)
    save_json(DEVICE, "x3dh_state", {
        "ik_dh_pub_b64": bundle["ik_dh_pub_b64"],
        "ik_sig_pub_b64": bundle["ik_sig_pub_b64"],
        "spk_pub_b64": bundle["spk_pub_b64"],
        "spk_signature_b64": bundle["spk_signature_b64"],
        "opk_privs_b64": [b64(p.private_bytes(encoding=3, format=1, encryption_algorithm=None)) for p in state.opk_privs],  
        "opk_pubs_b64": bundle["opk_pubs_b64"],
    })
    log(DEVICE, f"Registered X3DH bundle. Safety fingerprint: {safety_fingerprint(state.identity.ik_dh_pub)}")

    acc = Account()
    acc.generate_one_time_keys(10)
    id_key = acc.identity_keys["curve25519"]
    otks = list(acc.one_time_keys["curve25519"].values())
    post("/olm/publish", {"user_id": "bob", "id_key": id_key, "one_time_keys": otks})
    pickled = acc.pickle("bob-passphrase")
    save_json(DEVICE, "olm_state", {"pickle": pickled})
    log(DEVICE, "Published Olm id and one-time keys.")

def poll():
    olm_state = load_json(DEVICE, "olm_state")
    if not olm_state: raise SystemExit("Run register first.")
    acc = Account.from_pickle(olm_state["pickle"], "bob-passphrase")

    sess_cache = load_json(DEVICE, "session_inbound")
    sess = None
    if sess_cache:
        sess = Session.from_pickle(sess_cache["pickle"], "bob-passphrase")

    resp = get("/msg/poll", {"user_id": "bob"})
    for m in resp["messages"]:
        body = m["body"]
        if sess is None:
            s = Session()
            s.create_inbound(acc, body)
            acc.remove_one_time_keys(s)
            save_json(DEVICE, "olm_state", {"pickle": acc.pickle("bob-passphrase")})
            save_json(DEVICE, "session_inbound", {"pickle": s.pickle("bob-passphrase")})
            sess = s
            log(DEVICE, f"Created inbound Olm session from prekey message. Decrypted: {s.decrypt(body)}")
        else:
            try:
                p = sess.decrypt(body)
                log(DEVICE, f"Decrypted: {p}")
            except Exception as e:
                log(DEVICE, f"Decrypt error (tamper/replay likely): {e}")

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["register", "poll"])
    args = ap.parse_args()
    if args.cmd == "register": register()
    elif args.cmd == "poll": poll()
