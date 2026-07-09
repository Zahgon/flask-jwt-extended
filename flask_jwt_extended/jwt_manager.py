import datetime
from typing import Any
from typing import Callable
from typing import Optional

import jwt
from flask import Flask
from jwt import DecodeError
from jwt import ExpiredSignatureError
from jwt import InvalidAudienceError
from jwt import InvalidIssuerError
from jwt import InvalidTokenError
from jwt import MissingRequiredClaimError

from flask_jwt_extended.config import config
from flask_jwt_extended.default_callbacks import default_additional_claims_callback
from flask_jwt_extended.default_callbacks import default_blocklist_callback
from flask_jwt_extended.default_callbacks import default_decode_key_callback
from flask_jwt_extended.default_callbacks import default_encode_key_callback
from flask_jwt_extended.default_callbacks import default_expired_token_callback
from flask_jwt_extended.default_callbacks import default_invalid_token_callback
from flask_jwt_extended.default_callbacks import default_jwt_headers_callback
from flask_jwt_extended.default_callbacks import default_needs_fresh_token_callback
from flask_jwt_extended.default_callbacks import default_revoked_token_callback
from flask_jwt_extended.default_callbacks import default_token_verification_callback
from flask_jwt_extended.default_callbacks import (
    default_token_verification_failed_callback,
)
from flask_jwt_extended.default_callbacks import default_unauthorized_callback
from flask_jwt_extended.default_callbacks import default_user_identity_callback
from flask_jwt_extended.default_callbacks import default_user_lookup_error_callback
from flask_jwt_extended.exceptions import CSRFError
from flask_jwt_extended.exceptions import FreshTokenRequired
from flask_jwt_extended.exceptions import InvalidHeaderError
from flask_jwt_extended.exceptions import InvalidQueryParamError
from flask_jwt_extended.exceptions import JWTDecodeError
from flask_jwt_extended.exceptions import NoAuthorizationError
from flask_jwt_extended.exceptions import RevokedTokenError
from flask_jwt_extended.exceptions import UserClaimsVerificationError
from flask_jwt_extended.exceptions import UserLookupError
from flask_jwt_extended.exceptions import WrongTokenError
from flask_jwt_extended.tokens import _decode_jwt
from flask_jwt_extended.tokens import _encode_jwt
from flask_jwt_extended.typing import ExpiresDelta
from flask_jwt_extended.typing import Fresh
from flask_jwt_extended.utils import current_user_context_processor


class JWTManager(object):

    def __init__(
        self, app: Optional[Flask] = None, add_context_processor: bool = False
    ) -> None:
        """
        Create the JWTManager instance. You can either pass a flask application
        in directly here to register this extension with the flask app, or
        call init_app after creating this object (in a factory pattern).

        :param app:
            The Flask Application object
        :param add_context_processor:
            Controls if `current_user` is should be added to flasks template
            context (and thus be available for use in Jinja templates). Defaults
            to ``False``.
        """
        self._decode_key_callback = default_decode_key_callback
        self._encode_key_callback = default_encode_key_callback
        self._expired_token_callback = default_expired_token_callback
        self._invalid_token_callback = default_invalid_token_callback
        self._jwt_additional_header_callback = default_jwt_headers_callback
        self._needs_fresh_token_callback = default_needs_fresh_token_callback
        self._revoked_token_callback = default_revoked_token_callback
        self._token_in_blocklist_callback = default_blocklist_callback
        self._token_verification_callback = default_token_verification_callback
        self._unauthorized_callback = default_unauthorized_callback
        self._user_claims_callback = default_additional_claims_callback
        self._user_identity_callback = default_user_identity_callback
        self._user_lookup_callback: Optional[Callable] = None
        self._user_lookup_error_callback = default_user_lookup_error_callback
        self._token_verification_failed_callback = (
            default_token_verification_failed_callback
        )

        if app is not None:
            self.init_app(app, add_context_processor)

    def init_app(self, app: Flask, add_context_processor: bool = False) -> None:
        pass



    def additional_claims_loader(self, callback: Callable) -> Callable:
        pass

    def additional_headers_loader(self, callback: Callable) -> Callable:
        pass

    def decode_key_loader(self, callback: Callable) -> Callable:
        pass

    def encode_key_loader(self, callback: Callable) -> Callable:
        pass

    def expired_token_loader(self, callback: Callable) -> Callable:
        pass

    def invalid_token_loader(self, callback: Callable) -> Callable:
        pass

    def needs_fresh_token_loader(self, callback: Callable) -> Callable:
        pass

    def revoked_token_loader(self, callback: Callable) -> Callable:
        pass

    def token_in_blocklist_loader(self, callback: Callable) -> Callable:
        pass

    def token_verification_failed_loader(self, callback: Callable) -> Callable:
        pass

    def token_verification_loader(self, callback: Callable) -> Callable:
        pass

    def unauthorized_loader(self, callback: Callable) -> Callable:
        pass

    def user_identity_loader(self, callback: Callable) -> Callable:
        pass

    def user_lookup_loader(self, callback: Callable) -> Callable:
        pass

    def user_lookup_error_loader(self, callback: Callable) -> Callable:
        pass

    def _encode_jwt_from_config(
        self,
        identity: Any,
        token_type: str,
        claims=None,
        fresh: Fresh = False,
        expires_delta: Optional[ExpiresDelta] = None,
        headers=None,
    ) -> str:
        header_overrides = self._jwt_additional_header_callback(identity)
        if headers is not None:
            header_overrides.update(headers)

        claim_overrides = self._user_claims_callback(identity)
        if claims is not None:
            claim_overrides.update(claims)

        if expires_delta is None:
            if token_type == "access":
                expires_delta = config.access_expires
            else:
                expires_delta = config.refresh_expires

        return _encode_jwt(
            algorithm=config.algorithm,
            audience=config.encode_audience,
            claim_overrides=claim_overrides,
            csrf=config.cookie_csrf_protect,
            expires_delta=expires_delta,
            fresh=fresh,
            header_overrides=header_overrides,
            identity=self._user_identity_callback(identity),
            identity_claim_key=config.identity_claim_key,
            issuer=config.encode_issuer,
            json_encoder=config.json_encoder,
            secret=self._encode_key_callback(identity),
            token_type=token_type,
            nbf=config.encode_nbf,
        )

    def _decode_jwt_from_config(
        self, encoded_token: str, csrf_value=None, allow_expired: bool = False
    ) -> dict:
        unverified_claims = jwt.decode(
            encoded_token,
            algorithms=config.decode_algorithms,
            options={"verify_signature": False},
        )
        unverified_headers = jwt.get_unverified_header(encoded_token)
        secret = self._decode_key_callback(unverified_headers, unverified_claims)

        kwargs = {
            "algorithms": config.decode_algorithms,
            "audience": config.decode_audience,
            "csrf_value": csrf_value,
            "encoded_token": encoded_token,
            "identity_claim_key": config.identity_claim_key,
            "issuer": config.decode_issuer,
            "leeway": config.leeway,
            "secret": secret,
            "verify_aud": config.decode_audience is not None,
            "verify_sub": config.verify_sub,
        }

        try:
            return _decode_jwt(**kwargs, allow_expired=allow_expired)
        except ExpiredSignatureError as e:
            e.jwt_header = unverified_headers  # type: ignore
            e.jwt_data = _decode_jwt(**kwargs, allow_expired=True)  # type: ignore
            raise
