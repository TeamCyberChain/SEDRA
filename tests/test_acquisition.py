"""Acquisition regressions that protect benchmark provenance, without networking."""
import bz2
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "download_cert.py"
spec = importlib.util.spec_from_file_location("download_cert", MODULE)
download = importlib.util.module_from_spec(spec)
spec.loader.exec_module(download)


class AcquisitionTests(unittest.TestCase):
    def test_concatenated_bzip2_streams_extract_complete_member(self):
        content = b"id,date,user,pc,filename,content\n" + b"row,2010-01-01,u,pc,file,fictional\n" * 1000
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as bundle:
            entry = tarfile.TarInfo("r4.2/file.csv")
            entry.size = len(content)
            bundle.addfile(entry, io.BytesIO(content))
            ignored = tarfile.TarInfo("../../outside.txt")
            ignored.size = 3
            bundle.addfile(ignored, io.BytesIO(b"bad"))
        data = raw.getvalue()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "split.tar.bz2"
            # The stream boundary occurs inside the selected member body.
            archive.write_bytes(bz2.compress(data[:16000]) + bz2.compress(data[16000:]))
            result = download.extract_selected(archive, root / "selected")
            copied = root / "selected" / "file.csv"
            self.assertEqual(copied.read_bytes(), content)
            self.assertEqual(result[0]["bytes"], len(content))
            self.assertEqual(result[0]["sha256"], hashlib.sha256(content).hexdigest())
            self.assertFalse((root / "outside.txt").exists())
            self.assertEqual(len(json.loads((root / "selected" / "extraction_manifest.json").read_text())["members"]), 1)

    def test_existing_mismatched_download_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "archive"
            path.write_bytes(b"incomplete")
            with self.assertRaises(ValueError):
                download.fetch(path, "https://example.invalid/never-requested", 100, "0" * 64)
            self.assertEqual(path.read_bytes(), b"incomplete")


if __name__ == "__main__":
    unittest.main()
