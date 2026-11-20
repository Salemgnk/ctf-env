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

    def test_path_command(self):
        code, out, err = self.run_main("path")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("Aucun challenge en cours", err)
        self.run_main("new", "htb/cicada")
        self.assertEqual(self.run_main("path")[:2], (0, str(self.root / "htb" / "cicada") + "\n"))

    def test_help_and_unknown(self):
        self.assertEqual(self.run_main("--help")[0], 0)
        self.assertEqual(self.run_main("nimporte")[0], 2)


class TestTriage(Case):
    def setUp(self):
        super().setUp()
        self.d = ctf.challenge_new("epihack/x")
        self.f = self.d / "fichiers"

    def test_file_kind_by_extension(self):
        self.assertEqual(ctf.file_kind(Path("a.png")), "image")
        self.assertEqual(ctf.file_kind(Path("a.PCAPNG")), "pcap")
        self.assertEqual(ctf.file_kind(Path("a.zip")), "archive")
        self.assertEqual(ctf.file_kind(Path("a.docx")), "office")
        self.assertEqual(ctf.file_kind(Path("a.apk")), "apk")
        self.assertEqual(ctf.file_kind(Path("a.quelquechose")), "data")

    def test_file_kind_by_magic(self):
        elf = self.f / "sanssuffixe"
        shutil.copy("/usr/bin/true", elf)
        self.assertEqual(ctf.file_kind(elf), "elf")

    def test_category_for(self):
        self.assertEqual(ctf.category_for("image"), "stégano")
        self.assertEqual(ctf.category_for("pcap"), "forensic-réseau")
        self.assertEqual(ctf.category_for("elf"), "reverse")
        self.assertEqual(ctf.category_for("apk"), "reverse")
        self.assertEqual(ctf.category_for("pdf"), "forensic")
        self.assertEqual(ctf.category_for("archive"), "misc")

    def test_triage_commands_pick_tools(self):
        cmds = ctf.triage_commands(self.f / "a.png", "image")
        names = [c[0] for c in cmds]
        self.assertIn("exiftool", names)
        self.assertIn("zsteg", names)
        self.assertNotIn("zsteg", [c[0] for c in ctf.triage_commands(self.f / "a.jpg", "image")])
        self.assertIn("tshark", [c[0] for c in ctf.triage_commands(self.f / "a.pcap", "pcap")])

    def test_triage_writes_scan_and_sets_category(self):
        png = self.f / "flag.png"
        png.write_bytes(b"\x89PNG\r\n")
        with mock.patch.object(ctf, "run_tool", return_value="sortie outil"), \
             mock.patch.object(ctf, "file_desc", return_value="PNG image data"):
            res = ctf.triage(png)
        self.assertEqual(res["category"], "stégano")
        scan = self.d / "scans" / "flag.png.txt"
        self.assertTrue(scan.exists())
        self.assertIn("sortie outil", scan.read_text())
        self.assertEqual(ctf.challenge_category(self.d), "stégano")
        notes = (self.d / "notes.md").read_text()
        self.assertIn("flag.png", notes)
        self.assertIn("stégano", notes)

    def test_triage_keeps_first_category(self):
        ctf.set_category(self.d, "reverse")
        png = self.f / "a.png"
        png.write_bytes(b"x")
        with mock.patch.object(ctf, "run_tool", return_value=""), \
             mock.patch.object(ctf, "file_desc", return_value="PNG image data"):
            ctf.triage(png)
        self.assertEqual(ctf.challenge_category(self.d), "reverse")

    def test_run_tool_skips_missing(self):
        with mock.patch.object(ctf.shutil, "which", return_value=None):
            self.assertIn("non installé", ctf.run_tool(["outilbidon", "x"]))

    def test_ls_shows_category(self):
        ctf.set_category(self.d, "stégano")
        out = self.run_main("ls")[1]
        self.assertIn("stégano", out)
        self.assertIn("epihack/x", out)


class TestHints(Case):
    NMAP = """PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http      nginx 1.24.0
| http-auth:
|_  Basic realm=Zentara
255/tcp  filtered unknown
5030/tcp filtered surfpass
|_http-title: Did not follow redirect to http://doubletake.htb/
"""

    def setUp(self):
        super().setUp()
        self.d = ctf.challenge_new("htb/doubletake")

    def test_strip_ansi(self):
        self.assertEqual(ctf.strip_ansi("a\x1b[31mrouge\x1b[0mb\r"), "arougeb")

    def test_hints_detects_http_auth(self):
        hints = ctf.hints_from(self.NMAP)
        self.assertTrue(any("Basic" in h and "Zentara" in h for h in hints))

    def test_hints_detects_htb_host(self):
        self.assertTrue(any("doubletake.htb" in h and "/etc/hosts" in h for h in ctf.hints_from(self.NMAP)))

    def test_hints_lists_filtered_ports(self):
        h = " ".join(ctf.hints_from(self.NMAP))
        self.assertIn("255", h)
        self.assertIn("5030", h)

    def test_hints_dedup(self):
        hints = ctf.hints_from(self.NMAP + self.NMAP)
        self.assertEqual(len(hints), len(set(hints)))

    def test_new_hints_written_once(self):
        log = self.d / "scans" / "session-x.log"
        log.write_text(self.NMAP)
        first = ctf.new_hints(self.d)
        self.assertTrue(first)
        self.assertEqual(ctf.new_hints(self.d), [])
        notes = (self.d / "notes.md").read_text()
        self.assertIn("## Pistes", notes)
        self.assertIn("Zentara", notes)

    def test_log_command(self):
        with mock.patch.object(ctf.subprocess, "run", return_value=mock.Mock(returncode=0)) as run, \
             mock.patch.object(ctf.shutil, "which", return_value="/usr/bin/script"):
            code = self.run_main("log")[0]
        self.assertEqual(code, 0)
        args = run.call_args[0][0]
        self.assertEqual(args[0], "script")
        self.assertTrue(str(args[-1]).endswith(".log"))
        self.assertIn(str(self.d / "scans"), str(args[-1]))

    def test_log_needs_challenge(self):
        ctf.challenge_off()
        with mock.patch.object(ctf, "challenge_here", return_value=None):
            code, _, err = self.run_main("log")
        self.assertEqual(code, 1)
        self.assertIn("challenge", err.lower())


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

    def test_firefox_placeholder_waits_for_part(self):
        # Firefox crée a.zip vide à côté de a.zip.part pendant tout le téléchargement
        (self.dl / "a.zip").write_text("")
        part = self.dl / "a.zip.part"
        part.write_text("début")
        for t in (0.5, 3, 6):
            self.assertEqual(self.w.tick(t), [])
        part.write_text("contenu complet")
        os.replace(part, self.dl / "a.zip")
        self.w.tick(7)
        self.assertEqual(self.w.tick(9.5), [(self.dl / "a.zip", self.files / "a.zip")])
        self.assertEqual((self.files / "a.zip").read_text(), "contenu complet")

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

    def test_watch_notifies_with_category(self):
        (self.files / "n.png").write_bytes(b"x")
        calls = []
        with mock.patch.object(ctf, "triage", return_value={"category": "stégano"}), \
             mock.patch.object(ctf.subprocess, "run", side_effect=lambda *a, **k: calls.append(a[0])):
            ctf.notify([(self.dl / "n.png", self.files / "n.png")])
        self.assertEqual(calls[0][0], "notify-send")
        self.assertIn("n.png rangé dans htb/cicada [stégano]", " ".join(calls[0]))

    def test_service_file(self):
        unit = (Path(SCRIPT).parent / "ctf-downloads.service").read_text()
        self.assertIn("ExecStart=%h/.local/bin/ctf watch", unit)
        self.assertIn("WantedBy=default.target", unit)


class TestVpn(Case):
    def setUp(self):
        super().setUp()
        self.vpn = self.tmp / "config" / "vpn"
        self.cache = self.tmp / "cache"

    def add(self, name):
        self.vpn.mkdir(exist_ok=True)
        (self.vpn / name).write_text("client\n")

    def test_vpn_no_file_explains(self):
        code, _, err = self.run_main("vpn")
        self.assertEqual(code, 1)
        self.assertIn("Connection Pack", err)
        self.assertIn("ctf vpn add", err)

    def test_vpn_several_files_lists_them(self):
        self.add("lab_eu.ovpn")
        self.add("starting_point.ovpn")
        with mock.patch.object(ctf, "vpn_running", return_value=None), \
             mock.patch.object(ctf.subprocess, "run") as run:
            code, _, err = self.run_main("vpn")
        self.assertEqual(code, 1)
        self.assertIn("lab_eu", err)
        self.assertIn("starting_point", err)
        run.assert_not_called()

    def test_vpn_unknown_name(self):
        self.add("lab_eu.ovpn")
        code, _, err = self.run_main("vpn", "autre")
        self.assertEqual(code, 1)
        self.assertIn("lab_eu", err)

    def test_vpn_start_command(self):
        self.add("lab_eu.ovpn")
        done = mock.Mock(returncode=0)
        with mock.patch.object(ctf, "vpn_running", return_value=None), \
             mock.patch.object(ctf.subprocess, "run", return_value=done) as run, \
             mock.patch.object(ctf, "tun_ip", side_effect=[None, "10.10.14.7"]), \
             mock.patch.object(ctf.time, "sleep"):
            code, out, _ = self.run_main("vpn", "lab_eu")
        self.assertEqual(code, 0)
        self.assertEqual(run.call_args[0][0], [
            "sudo", "openvpn", "--config", str(self.vpn / "lab_eu.ovpn"), "--daemon",
            "--writepid", str(self.cache / "vpn.pid"), "--log", str(self.cache / "vpn.log")])
        self.assertIn("10.10.14.7", out)

    def test_vpn_timeout_shows_log(self):
        self.add("lab_eu.ovpn")
        (self.cache / "vpn.log").write_text("AUTH_FAILED\n")
        with mock.patch.object(ctf, "vpn_running", return_value=None), \
             mock.patch.object(ctf.subprocess, "run", return_value=mock.Mock(returncode=0)), \
             mock.patch.object(ctf, "tun_ip", return_value=None), \
             mock.patch.object(ctf.time, "sleep"):
            code, _, err = self.run_main("vpn")
        self.assertEqual(code, 1)
        self.assertIn("AUTH_FAILED", err)

    def test_vpn_already_running(self):
        self.add("lab_eu.ovpn")
        with mock.patch.object(ctf, "vpn_running", return_value=4242), \
             mock.patch.object(ctf, "tun_ip", return_value="10.10.14.7"), \
             mock.patch.object(ctf.subprocess, "run") as run:
            code, out, _ = self.run_main("vpn")
        self.assertEqual(code, 0)
        self.assertIn("déjà", out)
        self.assertIn("10.10.14.7", out)
        run.assert_not_called()

    def test_vpn_running_reads_pid(self):
        self.assertIsNone(ctf.vpn_running())
        (self.cache / "vpn.pid").write_text(f"{os.getpid()}\n")
        self.assertIsNone(ctf.vpn_running())  # PID vivant mais ce n'est pas openvpn
        with mock.patch.object(ctf, "proc_name", return_value="openvpn"):
            self.assertEqual(ctf.vpn_running(), os.getpid())
        (self.cache / "vpn.pid").write_text("999999999\n")
        self.assertIsNone(ctf.vpn_running())
        (self.cache / "vpn.pid").write_text("pas un pid")
        self.assertIsNone(ctf.vpn_running())

    def test_vpn_stop_never_kills_reused_pid(self):
        (self.cache / "vpn.pid").write_text(f"{os.getpid()}\n")
        with mock.patch.object(ctf.subprocess, "run") as run:
            self.assertEqual(self.run_main("vpn", "stop")[0], 0)
        run.assert_not_called()

    def test_vpn_add_copies(self):
        src = self.tmp / "lab_salem.ovpn"
        src.write_text("client\n")
        code, out, _ = self.run_main("vpn", "add", str(src))
        self.assertEqual(code, 0)
        self.assertTrue((self.vpn / "lab_salem.ovpn").exists())
        self.assertTrue(src.exists())
        self.assertEqual(self.run_main("vpn", "add", str(self.tmp / "absent.ovpn"))[0], 1)
        bad = self.tmp / "notes.txt"
        bad.write_text("x")
        self.assertEqual(self.run_main("vpn", "add", str(bad))[0], 1)

    def test_vpn_stop(self):
        code, out, _ = self.run_main("vpn", "stop")
        self.assertEqual(code, 0)
        self.assertIn("Aucune connexion", out)
        with mock.patch.object(ctf, "vpn_running", return_value=4242), \
             mock.patch.object(ctf.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            self.assertEqual(self.run_main("vpn", "stop")[0], 0)
        self.assertEqual(run.call_args[0][0], ["sudo", "kill", "4242"])

    def test_vpn_files_listed(self):
        self.add("b.ovpn")
        self.add("a.ovpn")
        (self.vpn / "notes.txt").write_text("x")
        self.assertEqual([p.name for p in ctf.vpn_files()], ["a.ovpn", "b.ovpn"])


if __name__ == "__main__":
    unittest.main()
