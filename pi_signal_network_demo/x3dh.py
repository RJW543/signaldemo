from dataclasses import dataclass
from typing import Optional, Tuple, List
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization, constant_time
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64, hashlib

def b64(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s.encode())

def hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    kdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return kdf.derive(ikm)

@dataclass
class Identity:
    user_id: str
    ik_dh_priv: x25519.X25519PrivateKey
    ik_dh_pub: bytes
    ik_sig_priv: ed25519.Ed25519PrivateKey
    ik_sig_pub: bytes

@dataclass
class ClientState:
    identity: Identity
    spk_priv: x25519.X25519PrivateKey
    spk_pub: bytes
    spk_signature: bytes
    opk_privs: List[x25519.X25519PrivateKey]
    opk_pubs: List[bytes]

def gen_identity(user_id: str) -> Identity:
    ik_dh_priv = x25519.X25519PrivateKey.generate()
    ik_dh_pub = ik_dh_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ik_sig_priv = ed25519.Ed25519PrivateKey.generate()
    ik_sig_pub = ik_sig_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return Identity(user_id, ik_dh_priv, ik_dh_pub, ik_sig_priv, ik_sig_pub)

def gen_client_state(identity: Identity, num_opks: int = 10) -> ClientState:
    spk_priv = x25519.X25519PrivateKey.generate()
    spk_pub = spk_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    spk_signature = identity.ik_sig_priv.sign(spk_pub)
    opk_privs = [x25519.X25519PrivateKey.generate() for _ in range(num_opks)]
    opk_pubs = [k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) for k in opk_privs]
    return ClientState(identity, spk_priv, spk_pub, spk_signature, opk_privs, opk_pubs)

def verify_spk_signature(ik_sig_pub: bytes, spk_pub: bytes, spk_signature: bytes) -> bool:
    pub = ed25519.Ed25519PublicKey.from_public_bytes(ik_sig_pub)
    try:
        pub.verify(spk_signature, spk_pub); return True
    except Exception: return False

def dh(priv: x25519.X25519PrivateKey, pub_bytes: bytes) -> bytes:
    pub = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
    return priv.exchange(pub)

@dataclass
class X3DHSecret:
    sk: bytes
    info: bytes

def safety_fingerprint(ik_dh_pub: bytes) -> str:
    return hashlib.sha256(ik_dh_pub).hexdigest()

def sender_x3dh(alice_identity: Identity,
                bob_ik_dh_pub: bytes, bob_ik_sig_pub: bytes,
                bob_spk_pub: bytes, bob_spk_signature: bytes,
                bob_opk_pub: Optional[bytes]) -> Tuple[X3DHSecret, bytes]:
    assert verify_spk_signature(bob_ik_sig_pub, bob_spk_pub, bob_spk_signature), "Invalid SPK signature"
    ek_priv = x25519.X25519PrivateKey.generate()
    ek_pub = ek_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    dh1 = dh(alice_identity.ik_dh_priv, bob_spk_pub)
    dh2 = dh(ek_priv, bob_ik_dh_pub)
    dh3 = dh(ek_priv, bob_spk_pub)
    dhs = [dh1, dh2, dh3]
    if bob_opk_pub is not None:
        dhs.append(dh(ek_priv, bob_opk_pub))
    ikm = b"".join(dhs)
    info = b"X3DH-network-demo"
    sk = hkdf(ikm, info, 32)
    return X3DHSecret(sk, info), ek_pub

def receiver_x3dh(bob_state: ClientState, alice_ek_pub: bytes, used_opk_pub: Optional[bytes]) -> X3DHSecret:
    dh1 = dh(bob_state.spk_priv, bob_state.identity.ik_dh_pub)
    dh2 = dh(bob_state.identity.ik_dh_priv, alice_ek_pub)
    dh3 = dh(bob_state.spk_priv, alice_ek_pub)
    dhs = [dh1, dh2, dh3]
    if used_opk_pub is not None:
        match = next((p for p, pub in zip(bob_state.opk_privs, bob_state.opk_pubs) if pub == used_opk_pub), None)
        if match is None: raise ValueError("OPK not found")
        dhs.append(dh(match, alice_ek_pub))
    ikm = b"".join(dhs)
    info = b"X3DH-network-demo"
    sk = hkdf(ikm, info, 32)
    return X3DHSecret(sk, info)
