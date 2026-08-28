import io


class PDFValidationError(ValueError):
    """Raised when an uploaded file fails structural PDF validation."""
    pass


class PDFValidator:
    """
    Validates uploaded PDF bytes before they touch the Volume or trigger
    a pipeline run. Operates on in-memory bytes, not a file path, since
    app.py has nothing on disk yet at the point this needs to run.
    """
    MAX_FILENAME_LENGTH = 255

    def __init__(
        self,
        filename: str,
        contents: bytes,
        max_file_size: int = 20 * 1024 * 1024,  # 20 MB
        min_file_size: int = 100,               # 100 bytes
    ):
        self.filename = filename
        self.contents = contents
        self.max_file_size = max_file_size
        self.min_file_size = min_file_size

    def validate(self):
        """Runs all checks. Raises PDFValidationError on the first failure."""
        self._validate_filename()
        self._sanitize_filename()
        self._check_extension()
        self._check_file_size()
        self._check_magic_bytes()
        self._check_eof_marker()
        return True

    # -------------------------------------------------------
    # Filename validation
    # -------------------------------------------------------

    def _validate_filename(self):
        if not self.filename:
            raise PDFValidationError("Filename is missing.")
        if len(self.filename) > self.MAX_FILENAME_LENGTH:
            raise PDFValidationError(
                f"Filename exceeds {self.MAX_FILENAME_LENGTH} characters."
            )

    def _sanitize_filename(self):
        if "\x00" in self.filename:
            raise PDFValidationError("Filename contains null byte.")
        if ".." in self.filename:
            raise PDFValidationError("Filename contains path traversal sequence.")

    def _check_extension(self):
        if not self.filename.lower().endswith(".pdf"):
            raise PDFValidationError("Invalid file extension. Expected .pdf")

    # -------------------------------------------------------
    # Content validation
    # -------------------------------------------------------

    def _check_file_size(self):
        size = len(self.contents)
        if size < self.min_file_size:
            raise PDFValidationError(
                f"File size below minimum threshold ({self.min_file_size} bytes)."
            )
        if size > self.max_file_size:
            raise PDFValidationError(
                f"File size exceeds maximum limit ({self.max_file_size} bytes)."
            )

    def _check_magic_bytes(self):
        if self.contents[:5] != b"%PDF-":
            raise PDFValidationError("Invalid PDF magic bytes. Missing '%PDF-' header.")

    def _check_eof_marker(self):
        tail = self.contents[-2048:]  # EOF marker normally sits in the last ~2KB
        if b"%%EOF" not in tail:
            raise PDFValidationError(
                "PDF EOF marker (%%EOF) not found. File may be truncated."
            )
