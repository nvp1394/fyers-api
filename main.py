from src.utils.functions import *
from src.config.secret import *
import sys

def run():

    # Step 1 - Retrieve request_key from send_login_otp API

    send_otp_result = send_login_otp(fy_id=FY_ID, app_id=APP_ID_TYPE)
    if send_otp_result[0] != SUCCESS:
        print(f"send_login_otp failure - {send_otp_result[1]}")
        sys.exit()
    else:
        print("send_login_otp success")

    # Step 2 - Generate totp
    generate_totp_result = generate_totp(secret=totp_secret)
    if generate_totp_result[0] != SUCCESS:
        print(f"generate_totp failure - {generate_totp_result[1]}")
        sys.exit()
    else:
        print("generate_totp success")
    # Step 3 - Verify totp and get request key from verify_otp API
    request_key = send_otp_result[1]
    totp = generate_totp_result[1]
    verify_totp_result = verify_totp(request_key=request_key, totp=totp)
    if verify_totp_result[0] != SUCCESS:
        print(f"verify_totp_result failure - {verify_totp_result[1]}")
        sys.exit()
    else:
        print("verify_totp_result success")

    # Step 4 - Verify pin and send back access token
    request_key_2 = verify_totp_result[1]
    verify_pin_result = verify_PIN(request_key=request_key_2, pin=pin)
    if verify_pin_result[0] != SUCCESS:
        print(f"verify_pin_result failure - {verify_pin_result[1]}")
        sys.exit()
    else:
        print("verify_pin_result success")
    # Step 5 - Get auth code for API V2 App from trade access token
    token_result = token(
        fy_id=FY_ID, app_id=app_id, redirect_uri=REDIRECT_URI, app_type=app_type,
        access_token=verify_pin_result[1]
    )
    if token_result[0] != SUCCESS:
        print(f"token_result failure - {token_result[1]}")
        sys.exit()
    else:
        print("token_result success")

    # Step 6 - Get API V2 access token from validating auth code
    auth_code = token_result[1]
    validate_authcode_result = validate_authcode(
        app_id_hash=APP_ID_HASH, auth_code=auth_code
    )

    if token_result[0] != SUCCESS:
        print(f"validate_authcode failure - {validate_authcode_result[1]}")
        sys.exit()
    else:
        print("validate_authcode success")

    data_api_call(access_token=validate_authcode_result[1], client_id=CLIENT_ID)

