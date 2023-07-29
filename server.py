import base64,itertools,hashlib,traceback,random
from flask import Flask, request, render_template_string, make_response
import requests, re, json, sys
from string import ascii_letters, digits
from typing import List, Union

possible_letters = ascii_letters + digits
a = Flask(__name__)
# bleh
true = True
false = False
the = json.load(open("me.json","r"))
gdpsMap = the["gdpsMap"]
dgjlParams = the["downloadGJLevelParams"]
@a.route("/")
def r():
    return render_template_string(open("./vocolo.html","r").read())

@a.route("/pyscript")
def rpy():
    return render_template_string(open("./python.html","r").read())

@a.route("/stealhenrysliver")
def getParams(): 
    return the

def xor_cipher(input:str, key:str):
    return ("").join(chr(ord(x) ^ ord(y)) for x, y in zip(input, itertools.cycle(key)))

def encode_gjp(password: str) -> str:
    # put it through the xor cipher with the key "37526"
    encoded = xor_cipher(password, "37526")
    # encode the password to base64
    encoded_base64 = base64.b64encode(encoded.encode()).decode()
    encoded_base64 = encoded_base64.replace("+", "-")
    encoded_base64 = encoded_base64.replace("/", "_")
    return encoded_base64

def resp2json(resp, fields=[]):
    print(resp)
    resp= resp.split("#")[0] #a
    r = re.compile("[^:]+:[^:]+")
    ret = {}
    check = (fields != [])
    for i in r.findall(resp):
        k,v = tuple(i.split(":"))
        if check:
            if k not in fields: continue
        ret[k] = v
    return ret

def generate_chk(values: List[Union[int,str]] = [], key: str = "", salt: str = "") -> str:
    values.append(salt)
    string = ("").join(map(str, values))  # assure "str" type and connect values
    hashed = hashlib.sha1(string.encode()).hexdigest()
    xored = xor_cipher(hashed, key)  # we discuss this one in encryption/xor
    final = base64.urlsafe_b64encode(xored.encode()).decode()
    return final

def generate_upload_seed(data: str, chars: int = 50):
    if len(data) < chars:
        return data  # not enough data to generate
    step = len(data) // chars
    return data[::step][:chars]

def generate_rs(n=10):
    return ("").join(random.choices(possible_letters, k=n))
#TODO: make this client side so rubrub won't block Render's ip address
@a.route("/reupload", methods=["POST","GET"])
def reuplaod():
    if request.method == "GET": return "hi"
    if request.method == "POST":
        target = request.json["target"]
        dest = request.json["dest"]
        levelId = request.json["levelId"]
        config = request.json["config"]

        error = false
        body = {}
        code = 200

        def setError(reason, status=404):
            nonlocal error, body, code
            error = true
            body = {"reason": reason}
            code = status
        try:
            if (target[0] not in gdpsMap or "https" in gdpsMap[target[0]]) or (dest[0] not in gdpsMap or "https" in gdpsMap[dest[0]]):
                setError("Server not supported or not exist")
            else:
                # downloadGJLevel22.php now requires rs and chk key so yeah that's my rs and chk
                accId = resp2json(requests.post(gdpsMap[dest[0]]+"getGJUsers20.php", data={"secret": "Wmfd2893gb7", "str":dest[1],"total": "0", "page":"0"}, headers={"User-Agent": ""}).text, ["16"]),
                accIdTarget = resp2json(requests.post(gdpsMap[target[0]]+"getGJUsers20.php", data={"secret": "Wmfd2893gb7", "str":target[1],"total": "0", "page":"0"}, headers={"User-Agent": ""}).text, ["16"]),
                rs=generate_rs()
                body2={"gameVersion": "21", "binaryVersion": "35","gdw":"0", "accountID":accIdTarget[0]["16"],"gjp": encode_gjp(target[2]), "uuid":"S1521388267807637760849071701082101002","udid":"147699869","levelID": levelId, "inc":"1", "extras":"0", "secret": "Wmfd2893gb7", "rs": rs, "chk": generate_chk([levelId, "1", rs, accIdTarget[0]["16"], "S1521388267807637760849071701082101002", "147699869"], "41274", "xI25fpAapCQg")}
                resp = resp2json(requests.post(gdpsMap[target[0]]+"downloadGJLevel22.php", data={k:body2[k] for k in body2 if k in dgjlParams}, headers={"User-Agent": ""}).text)
                upload = requests.post(gdpsMap[dest[0]]+"uploadGJLevel21.php", {
                    "gameVersion": 21,
                    "accountID": int(accId[0]["16"]),
                    "gjp": encode_gjp(dest[2]),
                    "userName": dest[1],
                    "levelID": 0,
                    "levelName": resp["2"],
                    "levelDesc": resp["3"],
                    "levelVersion": "1",
                    "levelLength": int(resp["15"]),
                    "audioTrack": int(resp["12"]),
                    "auto": 0,
                    "password": 0,#xor_cipher(base64.b64decode(resp["27"].encode()).decode(), "26364"),
                    "original": int(resp["30"] if "30" in resp else "0"),
                    "twoPlayer": int(resp["31"]),
                    "songID": int(config["songId"] if config["songId"] != 0 else resp["35"]),
                    "objects": 69420,
                    "coins": int(resp["37"]),
                    "requestedStars": int(resp["39"]),
                    "unlisted": "1" if config["unlisted"] else "0",
                    "ldm": 1,
                    "levelString": resp["4"]+"="*(-len(resp["4"])%4),
                    "seed2": generate_chk(key="41274", values=[generate_upload_seed(resp["4"])], salt="xI25fpAapCQg"),
                    "secret": "Wmfd2893gb7"
                })
                body = {"resp":"Level ID: "+upload.text}

        except Exception as e:
            setError(repr(e),500)
            traceback.print_tb(e.__traceback__)

        return make_response({"error": error, "body": body}, code)

notdebug=not (len(sys.argv)==2 and sys.argv[1] == "donotusedebugplsthanks")
a.run("0.0.0.0", port=10000, debug=notdebug)
