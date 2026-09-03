import io
import re

from pypdf import PdfReader


class PDFValidationError(ValueError):
    """Raised when an uploaded file fails PDF validation."""
    pass


class PDFValidator:
    """
    Validates uploaded PDF bytes before they touch the Volume or trigger
    a pipeline run. Operates on in-memory bytes, not a file path, since
    app.py has nothing on disk yet at the point this needs to run.

    Validation layers:
        1. Filename safety
        2. Cheap byte-level checks (header, EOF, version, malicious tokens)
        3. PDF bomb / resource exhaustion protection
        4. Deep parsed-PDF inspection (encryption, pages, metadata, text)
    """

    MAX_FILENAME_LENGTH = 255

    ALLOWED_VERSIONS = {
        b"%PDF-1.3",
        b"%PDF-1.4",
        b"%PDF-1.5",
        b"%PDF-1.6",
        b"%PDF-1.7",
        b"%PDF-2.0",
    }

    DANGEROUS_ACTIONS = (
        b"/JavaScript",
        b"/JS",
    )

    EXTERNAL_ACTIONS = (
        b"/GoToR",
        b"/Launch",
        b"/SubmitForm",
        b"/ImportData",
    )

    def __init__(
        self,
        filename: str,
        contents: bytes,
        max_file_size: int = 20 * 1024 * 1024,  # 20 MB
        min_file_size: int = 100,               # 100 bytes
        allow_forms: bool = False,
        allow_open_actions: bool = False,
        allow_xfa: bool = False,
        max_pages: int = 500,
        max_page_width: int = 5000,
        max_page_height: int = 5000,
        max_decompression_ratio: int = 100,
        max_text_chars: int = 10_000_000,
        max_objects: int = 100_000,
        max_xrefs: int = 20,
    ):
        self.filename = filename
        self.contents = contents
        self.max_file_size = max_file_size
        self.min_file_size = min_file_size

        self.allow_forms = allow_forms
        self.allow_open_actions = allow_open_actions
        self.allow_xfa = allow_xfa

        self.max_pages = max_pages
        self.max_page_width = max_page_width
        self.max_page_height = max_page_height
        self.max_decompression_ratio = max_decompression_ratio
        self.max_text_chars = max_text_chars
        self.max_objects = max_objects
        self.max_xrefs = max_xrefs

        self.reader = None
        self.pages = []
        self.page_count = 0

    # =========================================================
    # Public API
    # =========================================================

    def validate(self):
        """Runs all checks. Raises PDFValidationError on the first failure."""
        self._validate_filename()
        self._sanitize_filename()
        self._check_extension()

        self._check_file_size()
        self._check_magic_bytes()
        self._check_eof_marker()
        self._check_pdf_version()

        self._scan_malicious_actions()
        self._scan_open_actions()
        self._scan_acroforms()
        self._scan_xfa_forms()
        self._scan_embedded_files()
        self._scan_external_actions()

        self._check_object_count()
        self._check_incremental_updates()

        self.reader = self._parse_pdf()
        self._check_encryption()
        self.pages = list(self.reader.pages)

        
        self._check_page_count()
        self._check_page_dimensions()
        self._validate_metadata()

        self._check_decompression_ratio()
        self._check_text_size()

        return True

    # =========================================================
    # Filename validation
    # =========================================================

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

    # =========================================================
    # Basic content validation
    # =========================================================

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

    def _check_pdf_version(self):
        header = self.contents[:20]
        if not any(header.startswith(version) for version in self.ALLOWED_VERSIONS):
            raise PDFValidationError("Unsupported PDF version.")

    # =========================================================
    # Security validation
    # =========================================================

    def _scan_malicious_actions(self):
        for token in self.DANGEROUS_ACTIONS:
            if token in self.contents:
                raise PDFValidationError(
                    f"Dangerous PDF action detected: {token.decode(errors='ignore')}"
                )

    def _scan_open_actions(self):
        if self.allow_open_actions:
            return
        if b"/OpenAction" in self.contents:
            raise PDFValidationError("OpenAction entries are not permitted.")

    def _scan_acroforms(self):
        if self.allow_forms:
            return
        if b"/AcroForm" in self.contents:
            raise PDFValidationError("Interactive PDF forms are not permitted.")

    def _scan_xfa_forms(self):
        if self.allow_xfa:
            return
        if b"/XFA" in self.contents:
            raise PDFValidationError("XFA forms are not supported.")

    def _scan_embedded_files(self):
        if b"/EmbeddedFile" in self.contents:
            raise PDFValidationError("Embedded files are not allowed.")

    def _scan_external_actions(self):
        for token in self.EXTERNAL_ACTIONS:
            if token in self.contents:
                raise PDFValidationError(
                    f"External action detected: {token.decode(errors='ignore')}"
                )

    # =========================================================
    # PDF bomb / resource exhaustion protection
    # =========================================================

    def _check_object_count(self):
        object_count = len(re.findall(rb"\bobj\b", self.contents))
        if object_count > self.max_objects:
            raise PDFValidationError(f"PDF contains excessive objects ({object_count}).")

    def _check_incremental_updates(self):
        xref_count = self.contents.count(b"startxref")
        if xref_count > self.max_xrefs:
            raise PDFValidationError(
                f"PDF contains too many incremental updates ({xref_count})."
            )

    # =========================================================
    # Deep structural validation
    # =========================================================

    def _parse_pdf(self):
        try:
            return PdfReader(io.BytesIO(self.contents), strict=True)
        except Exception as exc:
            raise PDFValidationError(f"PDF cannot be parsed: {exc}") from exc

    def _check_encryption(self):
        if self.reader.is_encrypted:
            raise PDFValidationError("Password-protected PDFs are not supported.")

    def _check_page_count(self):
        self.page_count = len(self.pages)
        if self.page_count == 0:
            raise PDFValidationError("PDF contains no pages.")
        if self.page_count > self.max_pages:
            raise PDFValidationError(f"PDF exceeds maximum page limit ({self.max_pages}).")

    def _check_page_dimensions(self):
        for page_number, page in enumerate(self.pages, start=1):
            try:
                width = float(page.mediabox.width)
                height = float(page.mediabox.height)
            except Exception as exc:
                raise PDFValidationError(
                    f"Invalid page dimensions on page {page_number}: {exc}"
                ) from exc

            if width > self.max_page_width or height > self.max_page_height:
                raise PDFValidationError(
                    f"Page {page_number} exceeds maximum allowed dimensions."
                )

    def _validate_metadata(self):
        metadata = self.reader.metadata
        if not metadata:
            return

        suspicious_tokens = ("/JavaScript", "/JS", "<script")

        for value in metadata.values():
            if value is None:
                continue
            try:
                value = str(value)
            except Exception as exc:
                raise PDFValidationError(f"Invalid metadata value: {exc}") from exc

            for token in suspicious_tokens:
                if token.lower() in value.lower():
                    raise PDFValidationError("Suspicious metadata detected.")

    def _check_decompression_ratio(self):
        compressed_size = len(self.contents)
        if compressed_size == 0:
            raise PDFValidationError("Invalid empty PDF.")


        try:
            lenient_reader = PdfReader(io.BytesIO(self.contents),strict=False)
            lenient_pages = list(lenient_reader.pages)
        except Exception as exc:
            raise PDFValidationError('Unable to inspect PDF content streams: {exc}') from exc
        total_uncompressed = 0
        for page in self.pages:
            try:
                content = page.get_contents()
                if not content:
                    continue
                stream_data = content.get_data()
                total_uncompressed += len(stream_data)
            except Exception as exc:
                raise PDFValidationError(
                    f"Unable to inspect PDF content streams: {exc}"
                ) from exc

        ratio = total_uncompressed / compressed_size
        if ratio > self.max_decompression_ratio:
            raise PDFValidationError(
                f"Suspicious decompression ratio detected ({ratio:.2f})."
            )

    def _check_text_size(self):
        total_text_characters = 0
        for page_number, page in enumerate(self.pages, start=1):
            try:
                text = page.extract_text() or ""
            except Exception as exc:
                raise PDFValidationError(
                    f"Unable to extract text from page {page_number}: {exc}"
                ) from exc

            total_text_characters += len(text)
            if total_text_characters > self.max_text_chars:
                raise PDFValidationError(
                    "Extracted text exceeds maximum permitted size."
                )
