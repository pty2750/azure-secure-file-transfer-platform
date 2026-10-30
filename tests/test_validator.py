import unittest

from src.file_processor.validator import validate_file


class TestFileValidator(unittest.TestCase):

    # Existing functional tests

    def test_accepts_csv(self):
        result = validate_file("payment.csv", b"id,amount\n1,100")
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["sha256"]), 64)

    def test_accepts_pdf_extension(self):
        content = b"%PDF-1.4\nSample PDF content"
        result = validate_file("receipt.pdf", content)
        self.assertTrue(result["accepted"])

    def test_rejects_exe(self):
        result = validate_file("program.exe", b"content")
        self.assertEqual(result["status"], "rejected")

    def test_rejects_invalid_filename(self):
        result = validate_file("../payment.csv", b"content")
        self.assertFalse(result["accepted"])
        self.assertIn("Invalid filename.", result["errors"])

    def test_rejects_oversized_file(self):
        content = b"x" * (10 * 1024 * 1024 + 1)
        result = validate_file("large.csv", content)
        self.assertIn(
            "File exceeds the configured size limit.",
            result["errors"],
        )

    def test_checksum_is_repeatable(self):
        content = b"payment data"
        first = validate_file("payment.csv", content)
        second = validate_file("payment.csv", content)
        self.assertEqual(first["sha256"], second["sha256"])

    # Filename security tests

    def test_rejects_windows_path_traversal(self):
        result = validate_file("..\\..\\secret.txt", b"content")
        self.assertFalse(result["accepted"])
        self.assertIn("Invalid filename.", result["errors"])

    def test_rejects_absolute_path(self):
        result = validate_file("/etc/passwd.txt", b"content")
        self.assertFalse(result["accepted"])

    def test_rejects_windows_reserved_names(self):
        for filename in ("CON.txt", "NUL.csv", "COM1.pdf", "LPT1.txt"):
            with self.subTest(filename=filename):
                result = validate_file(filename, b"content")
                self.assertFalse(result["accepted"])
                self.assertIn("Invalid filename.", result["errors"])

    def test_rejects_filename_longer_than_255_characters(self):
        filename = "a" * 252 + ".csv"
        self.assertEqual(len(filename), 256)

        result = validate_file(filename, b"content")
        self.assertFalse(result["accepted"])
        self.assertIn("Invalid filename.", result["errors"])

    def test_rejects_consecutive_periods(self):
        result = validate_file("payment..csv", b"content")
        self.assertFalse(result["accepted"])

    def test_rejects_filename_ending_with_period(self):
        result = validate_file("payment.csv.", b"content")
        self.assertFalse(result["accepted"])

    def test_rejects_invalid_characters(self):
        for filename in ("payment file.csv", "payment$.csv", "payment\t.csv"):
            with self.subTest(filename=filename):
                result = validate_file(filename, b"content")
                self.assertFalse(result["accepted"])

    def test_rejects_non_string_filename(self):
        for filename in (None, 123, ["payment.csv"]):
            with self.subTest(filename=filename):
                result = validate_file(filename, b"content")
                self.assertFalse(result["accepted"])
                self.assertIn("Invalid filename.", result["errors"])

    # File content validation tests

    def test_rejects_pdf_without_pdf_signature(self):
        result = validate_file("invoice.pdf", b"This is ordinary text")
        self.assertFalse(result["accepted"])
        self.assertIn(
            "File content does not match the PDF format.",
            result["errors"],
        )

    def test_rejects_csv_with_binary_content(self):
        result = validate_file("payment.csv", b"id,amount\x00\x01")
        self.assertFalse(result["accepted"])
        self.assertIn("Text files must not contain null bytes.", result["errors"])

    def test_rejects_csv_with_invalid_utf8(self):
        result = validate_file("payment.csv", b"\xff\xfe\xfa")
        self.assertFalse(result["accepted"])
        self.assertIn(
            "Text files must contain valid UTF-8 content.",
            result["errors"],
        )

    def test_accepts_valid_utf8_text_file(self):
        result = validate_file("notes.txt", "Hello, world! नमस्ते".encode("utf-8"))
        self.assertTrue(result["accepted"])

    def test_accepts_valid_utf8_csv(self):
        result = validate_file(
            "payments.csv",
            "id,amount\n1,100\n2,200".encode("utf-8"),
        )
        self.assertTrue(result["accepted"])


if __name__ == "__main__":
    unittest.main()
