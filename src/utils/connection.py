import pyotp
import json
import requests
import pyotp
from urllib import parse
from fyers_api import fyersModel
from src.config.secret import URL_SEND_LOGIN_OTP,URL_VERIFY_TOTP, URL_VERIFY_PIN, URL_TOKEN, URL_VALIDATE_AUTH_CODE

def send_login_otp(fy_id, app_id):

    try:
        payload = {
            "fy_id": fy_id,
            "app_id": app_id
        }
 
        result_string = requests.post(url=URL_SEND_LOGIN_OTP, json=payload)
        if result_string.status_code != 200:
            return result_string.text
 
        result = json.loads(result_string.text)
        request_key = result["request_key"]
 
        return request_key
    except Exception as e:
        return e
def generate_totp(secret):
    try:
        generated_totp = pyotp.TOTP(secret).now()
        return generated_totp
    except Exception as e:
        return  e

def verify_totp(request_key, totp):

    try:
        payload = {
            "request_key": request_key,
            "otp": totp
        }
        result_string = requests.post(url=URL_VERIFY_TOTP, json=payload)
        if result_string.status_code != 200:
            return result_string.text
        result = json.loads(result_string.text)
        request_key = result["request_key"]
        return request_key

    except Exception as e:
        return e

def verify_PIN(request_key, pin):
    try:
        payload = {
            "request_key": request_key,
            "identity_type": "pin",
            "identifier": pin
        }
        result_string = requests.post(url=URL_VERIFY_PIN, json=payload)
        if result_string.status_code != 200:
            return result_string.text
        result = json.loads(result_string.text)
        access_token = result["data"]["access_token"]
        return access_token
    except Exception as e:
        return e
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
            return result_string.text

        result = json.loads(result_string.text)
        url = result["Url"]
        auth_code = parse.parse_qs(parse.urlparse(url).query)['auth_code'][0]

        return auth_code

    except Exception as e:
        return e

def validate_authcode(app_id_hash, auth_code):

    try:
        payload = {
            "grant_type": "authorization_code",
            "appIdHash": app_id_hash,
            "code": auth_code,
        }
        result_string = requests.post(url=URL_VALIDATE_AUTH_CODE, json=payload)
        if result_string.status_code != 200:
            return result_string.text
        result = json.loads(result_string.text)
        access_token = result["access_token"]
        return access_token
    except Exception as e:
        return e

def data_api_call(client_id, access_token):
	fyers = fyersModel.FyersModel(token=access_token,is_async=False,client_id=client_id) # Enter you desired log path store the logs on your system
	return fyers
	

    
	# history_data = {"symbol":"NSE:SBIN-EQ","resolution":"D","date_format":"0","range_from":"1678074300","range_to":"1679111100","cont_flag":"1"}
	# print(fyers.history(history_data))
	# print()

	# quotes_data = {"symbols": "NSE:SBIN-EQ"}
	# print(fyers.quotes(quotes_data))

 
