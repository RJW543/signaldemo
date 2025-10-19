from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64

app = FastAPI(title="E2EE Relay Demo")

bundles: Dict[str, dict] = {}           
opk_pools: Dict[str, List[str]] = {}    
olm_accounts: Dict[str, dict] = {}      
messages: Dict[str, List[dict]] = {}    

class UploadBundleRequest(BaseModel):
    user_id: str
    ik_dh_pub_b64: str
    ik_sig_pub_b64: str
    spk_pub_b64: str
    spk_signature_b64: str
    opk_pubs_b64: List[str]

class FetchBundleRequest(BaseModel):
    user_id: str

class FetchBundleResponse(BaseModel):
    ik_dh_pub_b64: str
    ik_sig_pub_b64: str
    spk_pub_b64: str
    spk_signature_b64: str
    opk_pub_b64: Optional[str]

class OlmPublishRequest(BaseModel):
    user_id: str
    id_key: str              
    one_time_keys: List[str] 

class OlmFetchRequest(BaseModel):
    user_id: str

class OlmFetchResponse(BaseModel):
    id_key: str
    one_time_key: Optional[str]

class SendMessageRequest(BaseModel):
    to: str
    sender: str
    body: dict               

class PollMessagesResponse(BaseModel):
    messages: List[dict]

@app.post("/bundle/upload")
def upload_bundle(req: UploadBundleRequest):
    bundles[req.user_id] = {
        "ik_dh_pub_b64": req.ik_dh_pub_b64,
        "ik_sig_pub_b64": req.ik_sig_pub_b64,
        "spk_pub_b64": req.spk_pub_b64,
        "spk_signature_b64": req.spk_signature_b64,
    }
    opk_pools[req.user_id] = list(req.opk_pubs_b64)
    return {"status": "ok", "opk_count": len(opk_pools[req.user_id])}

@app.post("/bundle/fetch", response_model=FetchBundleResponse)
def fetch_bundle(req: FetchBundleRequest):
    if req.user_id not in bundles:
        raise HTTPException(status_code=404, detail="bundle not found")
    bundle = bundles[req.user_id]
    opk = None
    if opk_pools.get(req.user_id):
        opk = opk_pools[req.user_id].pop(0)
    return FetchBundleResponse(
        ik_dh_pub_b64=bundle["ik_dh_pub_b64"],
        ik_sig_pub_b64=bundle["ik_sig_pub_b64"],
        spk_pub_b64=bundle["spk_pub_b64"],
        spk_signature_b64=bundle["spk_signature_b64"],
        opk_pub_b64=opk,
    )

@app.post("/olm/publish")
def olm_publish(req: OlmPublishRequest):
    olm_accounts[req.user_id] = {"id_key": req.id_key, "otks": list(req.one_time_keys)}
    return {"status": "ok", "otk_count": len(req.one_time_keys)}

@app.post("/olm/fetch", response_model=OlmFetchResponse)
def olm_fetch(req: OlmFetchRequest):
    if req.user_id not in olm_accounts:
        raise HTTPException(status_code=404, detail="olm account not found")
    acc = olm_accounts[req.user_id]
    otk = acc["otks"].pop(0) if acc["otks"] else None
    return OlmFetchResponse(id_key=acc["id_key"], one_time_key=otk)

@app.post("/msg/send")
def msg_send(req: SendMessageRequest):
    messages.setdefault(req.to, []).append({"from": req.sender, "body": req.body})
    return {"status": "queued", "queue_len": len(messages[req.to])}

@app.get("/msg/poll", response_model=PollMessagesResponse)
def msg_poll(user_id: str):
    q = messages.get(user_id, [])
    messages[user_id] = []
    return PollMessagesResponse(messages=q)

@app.get("/msg/peek")
def msg_peek(user_id: str):
    return {"queue": messages.get(user_id, [])}

@app.post("/msg/append")
def msg_append(req: SendMessageRequest):
    messages.setdefault(req.to, []).append({"from": req.sender, "body": req.body})
    return {"status": "appended", "queue_len": len(messages[req.to])}
