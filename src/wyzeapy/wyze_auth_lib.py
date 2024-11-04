import logging
import time
from typing import Dict, Any, Optional

import requests
import requests_cache
from .const import API_KEY, PHONE_ID, APP_NAME, APP_VERSION, SC, SV, PHONE_SYSTEM_TYPE, APP_VER, APP_INFO
from .exceptions import (
    UnknownApiError,
    TwoFactorAuthenticationEnabled,
    AccessTokenError,
)
from .utils import create_password, check_for_errors_standard

_LOGGER = logging.getLogger(__name__)

class Token:
    REFRESH_INTERVAL = 82800

    def __init__(self, access_token, refresh_token, refresh_time: float = None):
        self._access_token: str = access_token
        self._refresh_token: str = refresh_token
        self.expired = False
        if refresh_time:
            self._refresh_time: float = refresh_time
        else:
            self._refresh_time: float = time.time() + Token.REFRESH_INTERVAL

    @property
    def access_token(self):
        return self._access_token

    @access_token.setter
    def access_token(self, access_token):
        self._access_token = access_token
        self._refresh_time = time.time() + Token.REFRESH_INTERVAL

    @property
    def refresh_token(self):
        return self._refresh_token

    @refresh_token.setter
    def refresh_token(self, refresh_token):
        self._refresh_token = refresh_token

    @property
    def refresh_time(self):
        return self._refresh_time

class WyzeAuthLib:
    token: Optional[Token] = None
    SANITIZE_FIELDS = [
        "email",
        "password",
        "access_token",
        "accessToken",
        "refresh_token",
        "lat",
        "lon",
        "address",
    ]
    SANITIZE_STRING = "**Sanitized**"

    def __init__(
        self,
        username=None,
        password=None,
        key_id=None,
        api_key=None,
        token: Optional[Token] = None,
        token_callback=None,
    ):
        self._username = username
        self._password = password
        self._key_id = key_id
        self._api_key = api_key
        self.token = token
        self.session_id = ""
        self.verification_id = ""
        self.two_factor_type = None
        self.token_callback = token_callback

    @classmethod
    def create(
        cls,
        username=None,
        password=None,
        key_id=None,
        api_key=None,
        token: Optional[Token] = None,
        token_callback=None,
    ):
        self = cls(
            username=username,
            password=password,
            key_id=key_id,
            api_key=api_key,
            token=token,
            token_callback=token_callback,
        )

        if self._username is None and self._password is None and self.token is None:
            raise AttributeError("Must provide a username, password or token")
        elif self.token is None and self._username is not None and self._password is not None:
            assert self._username != ""
            assert self._password != ""

        return self

    def get_token_with_username_password(
        self, username, password, key_id, api_key
    ) -> Token:
        self._username = username
        self._password = create_password(password)
        self._key_id = key_id
        self._api_key = api_key
        login_payload = {"email": self._username, "password": self._password}

        headers = {
            "keyid": key_id,
            "apikey": api_key,
            "User-Agent": "wyzeapy",
        }

        response_json = self.post(
            "https://auth-prod.api.wyze.com/api/user/login",
            headers=headers,
            json=login_payload,
        )

        if response_json.get('errorCode') is not None:
            _LOGGER.error(f"Unable to login with response from Wyze: {response_json}")
            if response_json["errorCode"] == 1000:
                raise AccessTokenError
            raise UnknownApiError(response_json)

        if response_json.get('mfa_options') is not None:
            if "TotpVerificationCode" in response_json.get("mfa_options"):
                self.two_factor_type = "TOTP"
                self.verification_id = response_json["mfa_details"]["totp_apps"][0]["app_id"]
                raise TwoFactorAuthenticationEnabled
            if "PrimaryPhone" in response_json.get("mfa_options"):
                self.two_factor_type = "SMS"
                params = {
                    'mfaPhoneType': 'Primary',
                    'sessionId': response_json.get("sms_session_id"),
                    'userId': response_json['user_id'],
                }
                response_json = self.post('https://auth-prod.api.wyze.com/user/login/sendSmsCode',
                                          headers=headers, data=params)
                self.session_id = response_json['session_id']
                raise TwoFactorAuthenticationEnabled

        self.token = Token(response_json['access_token'], response_json['refresh_token'])
        self.token_callback(self.token)
        return self.token

    def get_token_with_2fa(self, verification_code) -> Token:
        headers = {
            'Phone-Id': PHONE_ID,
            'User-Agent': APP_INFO,
            'X-API-Key': API_KEY,
        }
        if self.two_factor_type == "TOTP":
            payload = {
                "email": self._username,
                "password": self._password,
                "mfa_type": "TotpVerificationCode",
                "verification_id": self.verification_id,
                "verification_code": verification_code
            }
        else:
            payload = {
                "email": self._username,
                "password": self._password,
                "mfa_type": "PrimaryPhone",
                "verification_id": self.session_id,
                "verification_code": verification_code
            }

        response_json = self.post(
            'https://auth-prod.api.wyze.com/user/login',
            headers=headers, json=payload)

        self.token = Token(response_json['access_token'], response_json['refresh_token'])
        self.token_callback(self.token)
        return self.token

    @property
    def should_refresh(self) -> bool:
        return time.time() >= self.token.refresh_time

    def refresh_if_should(self):
        if self.should_refresh or self.token.expired:
            _LOGGER.debug("Should refresh. Refreshing...")
            self.refresh()

    def refresh(self) -> None:
        payload = {
            "phone_id": PHONE_ID,
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "sc": SC,
            "sv": SV,
            "phone_system_type": PHONE_SYSTEM_TYPE,
            "app_ver": APP_VER,
            "ts": int(time.time()),
            "refresh_token": self.token.refresh_token
        }

        headers = {
            "X-API-Key": API_KEY
        }

        response = requests.post("https://api.wyzecam.com/app/user/refresh_token", headers=headers, json=payload)
        response_json = response.json()
        check_for_errors_standard(self, response_json)

        self.token.access_token = response_json['data']['access_token']
        self.token.refresh_token = response_json['data']['refresh_token']
        self.token_callback(self.token)
        self.token.expired = False

    def sanitize(self, data):
        if data and type(data) is dict:
            for key, value in data.items():
                if type(value) is dict:
                    data[key] = self.sanitize(value)
                if key in self.SANITIZE_FIELDS:
                    data[key] = self.SANITIZE_STRING
        return data

    def post(self, url, json=None, headers=None, data=None) -> Dict[Any, Any]:
        requests_cache.install_cache('wyze_cache')
        response = requests.post(url, json=json, headers=headers, data=data)
        _LOGGER.debug("Request:")
        _LOGGER.debug(f"url: {url}")
        _LOGGER.debug(f"json: {self.sanitize(json)}")
        _LOGGER.debug(f"headers: {self.sanitize(headers)}")
        _LOGGER.debug(f"data: {self.sanitize(data)}")
        try:
            response_json = response.json()
            _LOGGER.debug(f"Response Json: {self.sanitize(response_json)}")
        except requests.exceptions.ContentDecodingError:
            _LOGGER.debug(f"Response: {response}")
        return response.json()

    def put(self, url, json=None, headers=None, data=None) -> Dict[Any, Any]:
        requests_cache.install_cache('wyze_cache')
        response = requests.put(url, json=json, headers=headers, data=data)
        _LOGGER.debug("Request:")
        _LOGGER.debug(f"url: {url}")
        _LOGGER.debug(f"json: {self.sanitize(json)}")
        _LOGGER.debug(f"headers: {self.sanitize(headers)}")
        _LOGGER.debug(f"data: {self.sanitize(data)}")
        try:
            response_json = response.json()
            _LOGGER.debug(f"Response Json: {self.sanitize(response_json)}")
        except requests.exceptions.ContentDecodingError:
            _LOGGER.debug(f"Response: {response}")
        return response.json()

    def get(self, url, headers=None, params=None) -> Dict[Any, Any]:
        requests_cache.install_cache('wyze_cache')
        response = requests.get(url, params=params, headers=headers)
        _LOGGER.debug("Request:")
        _LOGGER.debug(f"url: {url}")
        _LOGGER.debug(f"headers: {self.sanitize(headers)}")
        _LOGGER.debug(f"params: {self.sanitize(params)}")
        try:
            response_json = response.json()
            _LOGGER.debug(f"Response Json: {self.sanitize(response_json)}")
        except requests.exceptions.ContentDecodingError:
            _LOGGER.debug(f"Response: {response}")
        return response.json()

    def patch(self, url, headers=None, params=None, json=None) -> Dict[Any, Any]:
        requests_cache.install_cache('wyze_cache')
        response = requests.patch(url, headers=headers, params=params, json=json)
        _LOGGER.debug("Request:")
        _LOGGER.debug(f"url: {url}")
        _LOGGER.debug(f"json: {self.sanitize(json)}")
        _LOGGER.debug(f"headers: {self.sanitize(headers)}")
        _LOGGER.debug(f"params: {self.sanitize(params)}")
        try:
            response_json = response.json()
            _LOGGER.debug(f"Response Json: {self.sanitize(response_json)}")
        except requests.exceptions.ContentDecodingError:
            _LOGGER.debug(f"Response: {response}")
        return response.json()

    def delete(self, url, headers=None, json=None) -> Dict[Any, Any]:
        requests_cache.install_cache('wyze_cache')
        response = requests.delete(url, headers=headers, json=json)
        _LOGGER.debug("Request:")
        _LOGGER.debug(f"url: {url}")
        _LOGGER.debug(f"json: {self.sanitize(json)}")
        _LOGGER.debug(f"headers: {self.sanitize(headers)}")
        try:
            response_json = response.json()
            _LOGGER.debug(f"Response Json: {self.sanitize(response_json)}")
        except requests.exceptions.ContentDecodingError:
            _LOGGER.debug(f"Response: {response}")
        return response.json()
```
