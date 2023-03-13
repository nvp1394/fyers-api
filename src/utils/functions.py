from ..config.secret import totp_secret, pin, app_id, app_type, secret_id
import pyotp
import json
import requests
import pyotp
from urllib import parse
import sys
import hashlib
from fyers_api import accessToken
from fyers_api import fyersModel

FY_ID = "XN11163"
APP_ID_TYPE = "2"
TOTP_KEY = totp_secret
PIN = pin
APP_ID = app_id
APP_TYPE = app_type
REDIRECT_URI = "http://127.0.0.1"
CLIENT_ID = f"{APP_ID}-{APP_TYPE}"
print(f"{app_id}:{secret_id}")
APP_ID_HASH = hashlib.sha256(f"{app_id}-{app_type}:{secret_id}".encode("utf-8")).hexdigest()
print(APP_ID_HASH)
# APP_ID_HASH = "8cc8eb5492894d9e6ff1b3eddba4e659ce178e*************************2"  # SHA-256 hash of appId-appType:appSecret

# API endpoints

BASE_URL = "https://api-t2.fyers.in/vagator/v2"
BASE_URL_2 = "https://api.fyers.in/api/v2"
URL_SEND_LOGIN_OTP = BASE_URL + "/send_login_otp"
URL_VERIFY_TOTP = BASE_URL + "/verify_otp"
URL_VERIFY_PIN = BASE_URL + "/verify_pin"
URL_TOKEN = BASE_URL_2 + "/token"
URL_VALIDATE_AUTH_CODE = BASE_URL_2 + "/validate-authcode"

SUCCESS = 1
ERROR = -1

def send_login_otp(fy_id, app_id):

    try:
        payload = {
            "fy_id": fy_id,
            "app_id": app_id
        }
 
        result_string = requests.post(url=URL_SEND_LOGIN_OTP, json=payload)
        if result_string.status_code != 200:
            return [ERROR, result_string.text]
 
        result = json.loads(result_string.text)
        request_key = result["request_key"]
 
        return [SUCCESS, request_key]
    except Exception as e:
        return [ERROR, e]
def generate_totp(secret):
    try:
        generated_totp = pyotp.TOTP(secret).now()
        return [SUCCESS, generated_totp]
    except Exception as e:
        return [ERROR, e]

def verify_totp(request_key, totp):

    try:
        payload = {
            "request_key": request_key,
            "otp": totp
        }
        result_string = requests.post(url=URL_VERIFY_TOTP, json=payload)
        if result_string.status_code != 200:
            return [ERROR, result_string.text]
        result = json.loads(result_string.text)
        request_key = result["request_key"]
        return [SUCCESS, request_key]

    except Exception as e:

        return [ERROR, e]

def verify_PIN(request_key, pin):
    try:
        payload = {
            "request_key": request_key,
            "identity_type": "pin",
            "identifier": pin
        }
        result_string = requests.post(url=URL_VERIFY_PIN, json=payload)
        if result_string.status_code != 200:
            return [ERROR, result_string.text]
        result = json.loads(result_string.text)
        access_token = result["data"]["access_token"]
        return [SUCCESS, access_token]
    except Exception as e:
        return [ERROR, e]
        result = json.loads(result_string.text)
        url = result["Url"]
        auth_code = parse.parse_qs(parse.urlparse(url).query)['auth_code'][0]
        return [SUCCESS, auth_code]
    except Exception as e:
        return [ERROR, e]
def token(fy_id, app_id, redirect_uri, app_type, access_token):
    try:
        payload = {
            "fyers_id": fy_id,
            "app_id": app_id,
            "redirect_uri": redirect_uri,
            "appType": app_type,
            "code_challenge": "",
            "state": "sample_state",
            "scope": "",
            "nonce": "",
            "response_type": "code",
            "create_cookie": True
        }
        headers={'Authorization': f'Bearer {access_token}'}

        result_string = requests.post(
            url=URL_TOKEN, json=payload, headers=headers
        )

        if result_string.status_code != 308:
            return [ERROR, result_string.text]

        result = json.loads(result_string.text)
        url = result["Url"]
        auth_code = parse.parse_qs(parse.urlparse(url).query)['auth_code'][0]

        return [SUCCESS, auth_code]

    except Exception as e:
        return [ERROR, e]

def validate_authcode(app_id_hash, auth_code):

    try:
        payload = {
            "grant_type": "authorization_code",
            "appIdHash": app_id_hash,
            "code": auth_code,
        }
        result_string = requests.post(url=URL_VALIDATE_AUTH_CODE, json=payload)
        if result_string.status_code != 200:
            return [ERROR, result_string.text]
        result = json.loads(result_string.text)
        access_token = result["access_token"]
        return [SUCCESS, access_token]
    except Exception as e:
        return [ERROR, e]

def data_api_call(client_id, access_token):
	fyers = fyersModel.FyersModel(token=access_token,is_async=False,client_id=client_id) # Enter you desired log path store the logs on your system
	
	print(fyers.get_profile())

	history_data = {"symbol":"NSE:SBIN-EQ","resolution":"D","date_format":"0","range_from":"1678074300","range_to":"1679111100","cont_flag":"1"}
	print(fyers.history(history_data))
	print()

	# quotes_data = {"symbols": "NSE:SBIN-EQ"}
	# print(fyers.quotes(quotes_data))

 
