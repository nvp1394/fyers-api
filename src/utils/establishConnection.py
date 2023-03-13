from .connection import *
from ..config.secret import FY_ID, APP_ID_TYPE, totp_secret, pin, REDIRECT_URI, app_id, app_type, APP_ID_HASH, CLIENT_ID
import logging
from datetime import datetime
import traceback

logging.basicConfig(filename=f"./logs/{datetime.now().date()}.log",
                    format='%(asctime)s %(message)s',
                    filemode='a')

logger = logging.getLogger()

logger.setLevel(logging.DEBUG)

def run():

    try:
        # Step 1 - Retrieve request_key from send_login_otp API
        send_otp_result = send_login_otp(fy_id=FY_ID, app_id=APP_ID_TYPE)
        logger.info("step 1: retrived otp results")
        # Step 2 - Generate totp
        generate_totp_result = generate_totp(secret=totp_secret)
        logger.info("step 2: totp generated")
        # Step 3 - Verify totp and get request key from verify_otp API
        verify_totp_result = verify_totp(request_key=send_otp_result, totp=generate_totp_result)
        logger.info("Verified totp sucessfully")
        # Step 4 - Verify pin and send back access token
        verify_pin_result = verify_PIN(request_key=verify_totp_result, pin=pin)
        logger.info("Verified login pin")
        # Step 5 - Get auth code for API V2 App from trade access token
        token_result = token(
            fy_id=FY_ID, app_id=app_id, redirect_uri=REDIRECT_URI, app_type=app_type,
            access_token=verify_pin_result
        )
        logger.info("Generated Authorization Code")
        # Step 6 - Get API V2 access token from validating auth code
        validate_authcode_result = validate_authcode(
            app_id_hash=APP_ID_HASH, auth_code=token_result
        )
        logger.info("Access token successfully generated")
        # Step 7 - Establish fyers connection.
        fyers = data_api_call(access_token=validate_authcode_result, client_id=CLIENT_ID)
        logger.info("Connection established with fyers api")
        logger.info(fyers.get_profile())
    except Exception as e:
        logger.critical(f"exception found: {e}")
        logger.critical(traceback.format_exc())

if __name__ == "__main__":
    run()