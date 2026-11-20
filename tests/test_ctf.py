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


class TestWatcher(Case):
    def setUp(self):
        super().setUp()
        (self.dl / "ancien.pdf").write_text("déjà là")
        self.w = ctf.Watcher(now=0)
        self.d = ctf.challenge_new("htb/cicada")
        self.files = self.d / "fichiers"

    def drop(self, name, data="x"):
        p = self.dl / name
        p.write_text(data)
        return p

    def test_existing_files_never_moved(self):
        for t in (1, 3, 6):
            self.assertEqual(self.w.tick(t), [])
        self.assertTrue((self.dl / "ancien.pdf").exists())

    def test_moves_new_file_after_stable(self):
        self.drop("obsidian_key.zip")
        self.assertEqual(self.w.tick(0.5), [])
        self.assertEqual(self.w.tick(1.5), [])
        moved = self.w.tick(2.6)
        self.assertEqual(moved, [(self.dl / "obsidian_key.zip", self.files / "obsidian_key.zip")])
        self.assertTrue((self.files / "obsidian_key.zip").exists())
        self.assertFalse((self.dl / "obsidian_key.zip").exists())

    def test_waits_until_size_stable(self):
        p = self.drop("lent.bin", "a")
        for t in range(1, 8):
            p.write_text("a" * (t + 1))
            self.assertEqual(self.w.tick(t), [], t)
        self.assertEqual(self.w.tick(10.5)[0][1], self.files / "lent.bin")

    def test_ignores_partial_and_hidden(self):
        for n in ("a.zip.crdownload", "b.part", "c.tmp", "d.download", ".cache"):
            self.drop(n)
        (self.dl / "dossier").mkdir()
        self.w.tick(1)
        self.assertEqual(self.w.tick(5), [])
        self.assertEqual(list(self.files.iterdir()), [])

    def test_partial_renamed_when_done(self):
        p = self.drop("big.zip.crdownload")
        self.w.tick(1)
        p.rename(self.dl / "big.zip")
        self.w.tick(2)
        self.assertEqual(self.w.tick(4.5)[0][1], self.files / "big.zip")

    def test_ovpn_goes_to_config(self):
        self.drop("lab_salem.ovpn")
        self.w.tick(0.5)
        moved = self.w.tick(3)
        self.assertEqual(moved[0][1], self.tmp / "config" / "vpn" / "lab_salem.ovpn")

    def test_ovpn_moved_even_without_current(self):
        ctf.challenge_off()
        self.drop("lab.ovpn")
        self.w.tick(0.5)
        self.assertEqual(self.w.tick(3)[0][1], self.tmp / "config" / "vpn" / "lab.ovpn")

    def test_collision_suffix(self):
        (self.files / "a.zip").write_text("premier")
        (self.files / "a (2).zip").write_text("deuxième")
        self.drop("a.zip", "troisième")
        self.w.tick(0.5)
        self.assertEqual(self.w.tick(3)[0][1], self.files / "a (3).zip")
        self.assertEqual((self.files / "a.zip").read_text(), "premier")
        self.assertEqual(ctf.free_name(self.files, "notes"), self.files / "notes")
        self.assertEqual(ctf.free_name(self.files, "a.zip"), self.files / "a (4).zip")

    def test_no_current_moves_nothing(self):
        ctf.challenge_off()
        self.drop("perso.pdf")
        self.w.tick(0.5)
        self.assertEqual(self.w.tick(3), [])
        ctf.challenge_use("htb/cicada")
        self.assertEqual(self.w.tick(6), [])
        self.assertTrue((self.dl / "perso.pdf").exists())

    def test_broken_current_moves_nothing(self):
        shutil.rmtree(self.d)
        self.drop("x.zip")
        self.w.tick(0.5)
        self.assertEqual(self.w.tick(3), [])
        self.assertTrue((self.dl / "x.zip").exists())

    def test_vanished_file_is_ignored(self):
        p = self.drop("parti.zip")
        self.w.tick(0.5)
        p.unlink()
        self.assertEqual(self.w.tick(3), [])

    def test_watch_notifies(self):
        self.drop("n.zip")
        calls = []
        with mock.patch.object(ctf.subprocess, "run", side_effect=lambda *a, **k: calls.append(a[0])):
            ctf.notify([(self.dl / "n.zip", self.files / "n.zip")])
        self.assertEqual(calls[0][0], "notify-send")
        self.assertIn("n.zip rangé dans htb/cicada", " ".join(calls[0]))

    def test_service_file(self):
        unit = (Path(SCRIPT).parent / "ctf-downloads.service").read_text()
        self.assertIn("ExecStart=%h/.local/bin/ctf watch", unit)
        self.assertIn("WantedBy=default.target", unit)


if __name__ == "__main__":
    unittest.main()
