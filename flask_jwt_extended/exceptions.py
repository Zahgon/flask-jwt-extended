class JWTExtendedException(Exception):

    pass


class JWTDecodeError(JWTExtendedException):

    pass


class InvalidHeaderError(JWTExtendedException):

    pass


class InvalidQueryParamError(JWTExtendedException):

    pass


class NoAuthorizationError(JWTExtendedException):

    pass


class CSRFError(JWTExtendedException):

    pass


class WrongTokenError(JWTExtendedException):

    pass


class RevokedTokenError(JWTExtendedException):

    def __init__(self, jwt_header: dict, jwt_data: dict) -> None:
        super().__init__("Token has been revoked")
        self.jwt_header = jwt_header
        self.jwt_data = jwt_data


class FreshTokenRequired(JWTExtendedException):

    def __init__(self, message, jwt_header: dict, jwt_data: dict) -> None:
        super().__init__(message)
        self.jwt_header = jwt_header
        self.jwt_data = jwt_data


class UserLookupError(JWTExtendedException):

    def __init__(self, message, jwt_header: dict, jwt_data: dict) -> None:
        super().__init__(message)
        self.jwt_header = jwt_header
        self.jwt_data = jwt_data


class UserClaimsVerificationError(JWTExtendedException):

    def __init__(self, message, jwt_header: dict, jwt_data: dict) -> None:
        super().__init__(message)
        self.jwt_header = jwt_header
        self.jwt_data = jwt_data
