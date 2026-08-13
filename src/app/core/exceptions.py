class ApiError(Exception):
    """Raised by API-layer code to produce a specific RFC 9457 problem response.

    Domain/application layers raise their own plain exceptions (no HTTP knowledge);
    routers catch those and translate them into an ApiError with the SRS-defined
    stable code."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        title: str,
        detail: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.title = title
        self.detail = detail
        self.headers = headers or {}
