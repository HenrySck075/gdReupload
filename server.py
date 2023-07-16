import base64,itertools
import hashlib
import traceback
from flask import Flask, request, render_template_string, make_response
import requests, re
a = Flask(__name__)
# bleh
true = True
false = False
gdpsMap = {
  "Geometry Dash": "http://www.boomlings.com/database/",
  "GDPS Editor 2.2": "http://game.gdpseditor.com/server/",
  "2.2 Unlocked": "https://smjs.eu/gd/unlock/database/",
  "1.9 GDPS": "https://absolllute.com/gdps/gdapi",
  "XGDPS": "https",
  "Zombie Dash": "https://zombiedashoficial.ddns.net/",
  "1.0 GDPS": "https://onezerogdps.7m.pl/",
  "1.4 GDPS": "https://onepoint4ps.7m.pl/",
  "1.6 GDPS": "https://discord.gg/eGWMmyk",
  "Aurora Dash": "https://aurorgdpsgd.7m.pl",
  "CnekGDPS": "https://cnekgdps.7m.pl/index.html/",
  "FloyzI GDPS": "https://discord.gg/jKRn5hy2f4",
  "Gaym 11 GDPS": "https://discord.gg/8z7YgxNP8j",
  "SilvrPS": "https://discord.gg/p2PStYUSGM",
  "WGDPS": "https://www.google.com"
}
@a.route("/")
def r():
    return render_template_string(open("./vocolo.html","r").read())

@a.route("/pyscript")
def rpy():
    return render_template_string(open("./index.html","r").read())

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
    resp= resp.split("#")[0] #a
    r = re.compile("[^:]+:[^:]+")
    ret = {}
    check = (fields != [])
    if check: print(resp)
    for i in r.findall(resp):
        k,v = tuple(i.split(":"))
        if check:
            if k not in fields: continue
        ret[k] = v
    return ret

def generate_chk(values: list[int, str] = [], key: str = "", salt: str = "") -> str:
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
            accId = resp2json(requests.post(gdpsMap[dest[0]]+"getGJUsers20.php", data={"secret": "Wmfd2893gb7", "str":dest[1],"total": "0", "page":"0"}, headers={"User-Agent": ""}).text, ["16"]),
            if (target[0] not in gdpsMap or "https" in gdpsMap[target[0]]) or (dest[0] not in gdpsMap or "https" in gdpsMap[dest[0]]):
                setError("Server not supported or not exist")
            else:
                # downloadGJLevel22.php now requires rs and chk key so yeah that's my rs and chk
                resp = resp2json(requests.post(gdpsMap[target[0]]+"downloadGJLevel22.php", data={"secret": "Wmfd2893gb7", "levelID": levelId, "gjp": encode_gjp(target[2]), "rs": "RQNMgw08Tm", "chk": "DAIFAAUDBlZSVQEHAQEBAVAFAwBXCAYOUVYCUAdSUAIGAwcAVwRUDQ==", "gdw": 0}, headers={"User-Agent": ""}).text)

                upload = requests.post(gdpsMap[dest[0]]+"uploadGJLevel21.php", {
                    "gameVersion": 21,
                    "accountID": int(accId[0]["16"]),
                    "gjp": encode_gjp(dest[2]),
                    "userName": dest[1],
                    "levelID": 0,
                    "levelName": resp["2"],
                    "levelDesc": "VGhpcyBsZXZlbCBpcyByZXVwbG9hZGVkIHVzaW5nIGEgYnJhbmQgbmV3IEdEIExldmVsIFJldXBsb2FkZXIgYnR3",#resp["3"],
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

a.run(port=5200, debug=True)