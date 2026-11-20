# ctf-env

Environnement de travail pour les CTF et les machines HTB : un dossier rangé par challenge, les téléchargements qui y arrivent tout seuls, le VPN en une commande, et des noms impacket qui marchent.

## Installation

```
./install.sh
```

Relançable, par exemple après une mise à jour d'impacket. Le script :

- crée le lien `~/.local/bin/ctf` ;
- crée `impacket-secretsdump`, `impacket-GetUserSPNs`... vers les scripts du paquet Arch `impacket` ;
- active le service utilisateur `ctf-downloads` ;
- ajoute la fonction `cdc` à `~/.zshrc`.

## Utilisation

```
ctf new htb/cicada 10.10.11.35   crée ~/Documents/ctf/htb/cicada et le met en cours
ctf use htb/cicada               reprend un challenge
ctf off                          plus de challenge en cours
ctf ls                           liste des challenges
ctf                              challenge en cours, VPN, rangement
cdc                              cd dans le challenge en cours
ctf vpn [nom]                    connexion VPN (sudo)
ctf vpn add fichier.ovpn         ajoute un fichier VPN
ctf vpn stop                     coupe le VPN
```

Chaque challenge contient `notes.md`, `fichiers/` et `scans/`.

## Tri des artefacts

Quand un fichier arrive dans un challenge, il est identifié selon son type (exiftool, binwalk, zsteg pour une image ; file, checksec, strings pour un binaire ; tshark pour une capture...). Le détail va dans `scans/<fichier>.txt`, un résumé et une catégorie devinée (stégano, reverse, forensic, forensic-réseau, crypto, misc) dans `notes.md`. La catégorie s'affiche dans `ctf ls` et la notification ; corrige-la dans `.categorie` si besoin.

## Session et pistes

```
ctf log      enregistre ta session (commandes et sorties) dans scans/session-<date>.log
ctf hints    affiche les pistes repérées
```

Pendant un `ctf log`, le service lit le journal et pousse des pistes par notification : authentification HTTP Basic, nom `.htb` à mettre dans `/etc/hosts`, ports filtrés, service web à énumérer. Les pistes s'ajoutent à la section `## Pistes` de `notes.md`, sans doublon.

## Téléchargements

Tant qu'un challenge est en cours, chaque nouveau fichier de `~/Downloads` est déplacé dans son dossier `fichiers/`, une fois le téléchargement terminé, avec une notification. Les `.ovpn` vont dans `~/.config/ctf/vpn/`, même sans challenge en cours. Les fichiers déjà présents, ou arrivés sans challenge en cours, ne bougent pas.

Journal du service : `journalctl --user -u ctf-downloads`.

## Tests

```
python3 -m unittest discover -s tests -v
```
