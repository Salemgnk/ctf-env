"""Tests de ctf. Lancer : python3 -m unittest discover -s tests -v"""
import sys
sys.dont_write_bytecode = True
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = str(Path(__file__).resolve().parent.parent / "ctf")


def load():
    loader = importlib.machinery.SourceFileLoader("ctf_mod", SCRIPT)
    spec = importlib.util.spec_from_loader("ctf_mod", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


ctf = load()


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        env = {}
        for k in ("root", "config", "cache", "downloads"):
            d = self.tmp / k
            d.mkdir()
            env[f"CTF_{k.upper()}"] = str(d)
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        self.root = self.tmp / "root"
        self.dl = self.tmp / "downloads"

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ctf.main(list(argv))
        return code, out.getvalue(), err.getvalue()


class TestChallenges(Case):
    def test_parse_name(self):
        self.assertEqual(ctf.parse_name("htb/cicada"), ("htb", "cicada"))
        self.assertEqual(ctf.parse_name("epihack-2026/obsidian-key"), ("epihack-2026", "obsidian-key"))
        for bad in ("cicada", "HTB/x", "htb/../x", "a/b/c", "htb/", "/x", "htb/x y"):
            with self.assertRaises(ValueError, msg=bad):
                ctf.parse_name(bad)

    def test_new_creates_layout(self):
        code, out, _ = self.run_main("new", "htb/cicada", "10.10.11.35")
        d = self.root / "htb" / "cicada"
        self.assertEqual(code, 0)
        for sub in ("fichiers", "scans"):
            self.assertTrue((d / sub).is_dir())
        notes = (d / "notes.md").read_text()
        self.assertIn("# htb/cicada", notes)
        self.assertIn("10.10.11.35", notes)
        for section in ("Cible", "Ports et services", "Identifiants", "Étapes", "Flags"):
            self.assertIn(section, notes)
        self.assertEqual(ctf.current(), d)
        self.assertIn(str(d), out)

    def test_new_existing_keeps_notes(self):
        self.run_main("new", "htb/cicada")
        notes = self.root / "htb" / "cicada" / "notes.md"
        notes.write_text("mes notes")
        self.run_main("off")
        self.assertEqual(self.run_main("new", "htb/cicada")[0], 0)
        self.assertEqual(notes.read_text(), "mes notes")
        self.assertEqual(ctf.current(), notes.parent)

    def test_new_bad_name(self):
        code, _, err = self.run_main("new", "cicada")
        self.assertEqual(code, 1)
        self.assertIn("groupe/nom", err)

    def test_use_and_off(self):
        code, _, err = self.run_main("use", "htb/absent")
        self.assertEqual(code, 1)
        self.assertIn("n'existe pas", err)
        self.run_main("new", "htb/a")
        self.run_main("new", "htb/b")
        self.assertEqual(self.run_main("use", "htb/a")[0], 0)
        self.assertEqual(ctf.current(), self.root / "htb" / "a")
        self.run_main("off")
        self.assertIsNone(ctf.current())
        self.assertEqual(self.run_main("off")[0], 0)

    def test_ls_order_and_ignores_loose_files(self):
        (self.root / "vrac.zip").write_text("x")
        (self.root / "jadx_out").mkdir()
        self.run_main("new", "htb/vieux")
        self.run_main("new", "epihack/recent")
        old = self.root / "htb" / "vieux" / "notes.md"
        os.utime(old, (time.time() - 3600, time.time() - 3600))
        self.assertEqual(ctf.challenges(), [self.root / "epihack" / "recent", self.root / "htb" / "vieux"])
        out = self.run_main("ls")[1]
        self.assertLess(out.index("epihack/recent"), out.index("htb/vieux"))
        self.assertNotIn("vrac", out)

    def test_status_broken_current(self):
        self.run_main("new", "htb/cicada")
        shutil.rmtree(self.root / "htb" / "cicada")
        self.assertIsNone(ctf.current())
        with mock.patch.object(ctf, "tun_ip", return_value=None, create=True), \
             mock.patch.object(ctf, "service_state", return_value="inactif", create=True):
            code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("n'existe plus", out)

    def test_status_without_current(self):
        with mock.patch.object(ctf, "tun_ip", return_value=None, create=True), \
             mock.patch.object(ctf, "service_state", return_value="inactif", create=True):
            code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("Aucun challenge en cours", out)

    def test_help_and_unknown(self):
        self.assertEqual(self.run_main("--help")[0], 0)
        self.assertEqual(self.run_main("nimporte")[0], 2)


if __name__ == "__main__":
    unittest.main()
