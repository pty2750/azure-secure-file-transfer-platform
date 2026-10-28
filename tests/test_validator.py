
import unittest

from src.file_processor.validator import validate_file


class TestFileValidator(unittest.TestCase):

    def test_accepts_csv(self):
        result = validate_file("payment.csv", b"id,amount\n1,100")
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["sha256"]), 64)

    def test_accepts_pdf_extension(self):
        result = validate_file("receipt.pdf", b"sample PDF content")
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


if __name__ == "__main__":
    unittest.main()
