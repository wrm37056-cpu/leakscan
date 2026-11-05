import os
import tempfile
import unittest

from leakscan import main, scan_paths, scan_text

# Fake secrets are built by concatenation so this file doesn't trip the scanner itself.
FAKE = {
    "AWS access key": "AKIA" + "IOSFODNN7EXAMPLE",
    "GitHub token": "gh" + "p_" + "a" * 36,
    "Slack token": "xo" + "xb-" + "1234567890-abc",
    "Private key": "-----BEGIN RSA " + "PRIVATE KEY-----",
    "Generic secret": "api_key = " + '"' + "s3cr3tvalue123" + '"',
}


class ScanTextTest(unittest.TestCase):
    def test_detects_each_type(self):
        for name, sample in FAKE.items():
            with self.subTest(name=name):
                self.assertIn((1, name), list(scan_text(sample)))

    def test_clean_text(self):
        self.assertEqual(list(scan_text("password = input()\nhello world\n")), [])

    def test_line_numbers(self):
        text = "ok\nok\n" + FAKE["AWS access key"] + "\n"
        self.assertEqual(list(scan_text(text)), [(3, "AWS access key")])


class ScanPathsTest(unittest.TestCase):
    def test_folder_scan_skips_git_and_binary(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "config.py"), "w", encoding="utf-8") as f:
                f.write(FAKE["GitHub token"])
            os.mkdir(os.path.join(d, ".git"))
            with open(os.path.join(d, ".git", "x"), "w", encoding="utf-8") as f:
                f.write(FAKE["GitHub token"])
            with open(os.path.join(d, "img.bin"), "wb") as f:
                f.write(b"\xff\xfe\x00\x81")
            results = list(scan_paths([d]))
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0][0].endswith("config.py"))

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main([d]), 0)
            with open(os.path.join(d, "a.txt"), "w", encoding="utf-8") as f:
                f.write(FAKE["Private key"])
            self.assertEqual(main([d]), 1)


if __name__ == "__main__":
    unittest.main()
