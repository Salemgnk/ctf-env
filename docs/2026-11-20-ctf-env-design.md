# Environnement CTF et HTB : conception

20 novembre 2026.

## Pourquoi

Trois choses font perdre du temps à chaque challenge :

1. retrouver le fichier `.ovpn` HTB pour se connecter ;
2. les fichiers téléchargés arrivent dans `~/Downloads`, mélangés au reste, au lieu du dossier du challenge ;
3. les outils impacket ont des « chemins cassés ».

Constat pour le point 3 : impacket 0.13.1 est installé deux fois, par pacman (104 scripts `*.py` dans `/usr/bin`) et par `pip --user` (74 scripts dans `~/.local/bin`, qui passent devant dans le PATH). Les noms façon Kali utilisés dans les writeups (`impacket-secretsdump`, ...) n'existent pas. L'installation pip a aussi amené `pyasn1` 0.4.8, qui masque celui du système pour tout programme Python.

## Objectifs

- Une commande `ctf` comme point d'entrée unique.
- Un dossier rangé par challenge, avec un challenge « en cours ».
- Téléchargements déplacés automatiquement dans le challenge en cours (choix de l'utilisateur : automatique plutôt qu'à la demande).
- VPN HTB en une commande.
- Impacket cohérent, appelable sous les deux noms.

## Hors périmètre

- Installer de nouveaux outils d'attaque : presque tout est déjà là (BlackArch configuré).
- Conteneur ou machine virtuelle (Exegol, etc.) : 27 Go libres, et ça ne règle ni les téléchargements ni le rangement.
- `/etc/hosts`, variables `$IP`, prise de notes avancée : possibles plus tard.
- Toucher aux fichiers déjà présents dans `~/Documents/ctf`.

## Approches envisagées

1. **Outil `ctf` en Python + service utilisateur systemd pour les téléchargements** (retenue, acceptée par l'utilisateur) : un seul script testable, comme `claude-history`.
2. Fonctions zsh dans `.zshrc` : peu testable, et le service resterait nécessaire.
3. Exegol : trop lourd pour le disque, ne règle pas les deux premiers points.

## Comportement

### Challenges

| Commande | Effet |
|---|---|
| `ctf new <groupe>/<nom> [ip]` | crée `~/Documents/ctf/<groupe>/<nom>/` et le marque en cours ; ex. `ctf new htb/cicada 10.10.11.35`, `ctf new epihack-2026/obsidian-key` |
| `ctf use <groupe>/<nom>` | reprend un challenge existant comme challenge en cours |
| `ctf off` | plus de challenge en cours (les téléchargements restent dans `~/Downloads`) |
| `ctf` | où on en est : challenge en cours et son chemin, état du VPN et IP `tun0`, état du service |
| `ctf ls` | liste des challenges, les plus récents d'abord |
| `cdc` | fonction zsh : `cd` dans le challenge en cours |

Contenu d'un challenge : `notes.md` (modèle : cible, IP, ports, identifiants, étapes, flags), `fichiers/` (les téléchargements), `scans/`.
Nom : minuscules, chiffres, tirets ; le groupe est obligatoire (`htb`, nom de l'événement...).
L'état « en cours » est un lien `~/Documents/ctf/.courant` vers le dossier du challenge.

### Téléchargements

- Service `ctf-downloads.service` (systemd utilisateur, démarré à l'ouverture de session) qui lance `ctf watch`.
- Toutes les secondes, regarde `~/Downloads`. Un fichier apparu depuis le démarrage du service est déplacé quand sa taille n'a pas bougé pendant 2 secondes.
- Ignore les téléchargements en cours (`.crdownload`, `.part`, `.tmp`, `.download`) et les fichiers cachés.
- Les `.ovpn` vont dans `~/.config/ctf/vpn/` au lieu du challenge.
- Sans challenge en cours, rien ne bouge.
- Si le nom existe déjà dans `fichiers/`, ajoute ` (2)`, ` (3)`...
- Notification `notify-send` : « obsidian_key.zip rangé dans epihack-2026/obsidian-key ».
- Les fichiers déjà présents dans `~/Downloads` ne sont jamais touchés.

### VPN

- Fichiers `.ovpn` dans `~/.config/ctf/vpn/` (rangés automatiquement depuis les téléchargements, ou `ctf vpn add <fichier>`).
- `ctf vpn [nom]` : `sudo openvpn` en arrière-plan avec journal dans `~/.cache/ctf/vpn.log`, attend `tun0` et affiche l'IP. Sans nom : le seul fichier présent, ou la liste s'il y en a plusieurs. Aucun fichier : explique où le télécharger sur HTB.
- `ctf vpn stop` : arrête la connexion. `ctf` affiche l'état.
- Pas de nouveau paquet : `openvpn` est déjà installé (le greffon NetworkManager ne l'est pas).

### Impacket

- On garde le paquet Arch. Retrait de la copie `pip --user` d'impacket et des dépendances qu'elle seule utilise, **après avoir montré la liste exacte à l'utilisateur**.
- Liens `impacket-<nom>` dans `~/.local/bin` vers chaque `/usr/bin/<nom>.py` du paquet (`impacket-secretsdump`, `impacket-GetUserSPNs`...). Recréés par `install.sh`, relançable après une mise à jour.

## Réalisation

- Dépôt git local `~/Documents/ctf-env` : `ctf` (Python, bibliothèque standard seulement), `install.sh`, `ctf-downloads.service`, `tests/`, `docs/`, `README.md`.
- `install.sh` : lien `~/.local/bin/ctf`, liens impacket, service activé, fonction `cdc` ajoutée à `~/.zshrc` dans un bloc balisé.
- Commits sans ligne `Co-Authored-By`.

## Laissé au constructeur

Format exact de l'affichage de `ctf`, texte du modèle `notes.md`, délai d'attente de `tun0` (proposé : 15 s).
