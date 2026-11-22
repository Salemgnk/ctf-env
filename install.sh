#!/usr/bin/env bash
# Installe ctf : commande, noms impacket façon Kali, service de rangement, fonction cdc.
# Relançable sans risque, par exemple après une mise à jour d'impacket.
set -euo pipefail

src="${BASH_SOURCE[0]:-$0}"
here="$(cd "$(dirname "$src")" 2>/dev/null && pwd || true)"

# Lancé via « curl -fsSL .../install.sh | bash » : pas de fichiers sous la main,
# on clone le dépôt puis on relance l'install depuis la copie.
if [ -z "${here:-}" ] || [ ! -f "$here/ctf" ]; then
  if ! command -v git >/dev/null 2>&1; then
    echo "git est nécessaire pour cette installation." >&2
    exit 1
  fi
  repo="https://github.com/Salemgnk/ctf-env.git"
  dest="${XDG_DATA_HOME:-$HOME/.local/share}/ctf-env"
  echo "Récupération de ctf-env dans $dest..."
  if [ -d "$dest/.git" ]; then
    git -C "$dest" pull --ff-only -q || true
  else
    git clone -q "$repo" "$dest"
  fi
  exec bash "$dest/install.sh"
fi

bin="$HOME/.local/bin"
mkdir -p "$bin"

# 1. Commande ctf
ln -sf "$here/ctf" "$bin/ctf"
echo "ctf -> $bin/ctf"

# 2. Noms impacket-<outil> vers les scripts du paquet Arch
if pacman -Q impacket >/dev/null 2>&1; then
  n=0
  while IFS= read -r f; do
    case "$f" in /usr/bin/*.py) ;; *) continue ;; esac
    tool="$(basename "$f" .py)"
    ln -sf "$f" "$bin/impacket-$tool"
    n=$((n + 1))
  done < <(pacman -Qlq impacket)
  echo "$n commandes impacket-<outil> dans $bin"
else
  echo "Paquet impacket absent : noms impacket-<outil> non créés (sudo pacman -S impacket)." >&2
fi

# 3. Service de rangement des téléchargements
unit_dir="$HOME/.config/systemd/user"
mkdir -p "$unit_dir"
install -m 644 "$here/ctf-downloads.service" "$unit_dir/ctf-downloads.service"
systemctl --user daemon-reload
systemctl --user enable --now ctf-downloads.service >/dev/null 2>&1
systemctl --user restart ctf-downloads.service
echo "service ctf-downloads : $(systemctl --user is-active ctf-downloads.service)"

# 4. Complétions shell (Tab)
data="${XDG_DATA_HOME:-$HOME/.local/share}"
bdir="$data/bash-completion/completions"
zdir="$data/zsh/site-functions"
mkdir -p "$bdir" "$zdir"
install -m644 "$here/completions/ctf.bash" "$bdir/ctf"
install -m644 "$here/completions/_ctf" "$zdir/_ctf"
echo "complétion Tab installée (bash et zsh)"

# 5. Fonction cdc + fpath dans ~/.zshrc, dans un bloc balisé remplacé à chaque installation
rc="$HOME/.zshrc"
touch "$rc"
start="# >>> ctf-env >>>"
end="# <<< ctf-env <<<"
tmp="$(mktemp)"
awk -v s="$start" -v e="$end" '$0==s{skip=1} !skip{print} $0==e{skip=0}' "$rc" > "$tmp"
{
  cat "$tmp"
  echo "$start"
  echo '# cd dans le challenge en cours (voir ctf)'
  echo 'cdc() { local d; d="$(ctf path)" && cd "$d"; }'
  echo "fpath=(\"$zdir\" \$fpath); autoload -Uz compinit; compinit"
  echo "$end"
} > "$rc"
rm -f "$tmp"
echo "fonction cdc + complétion ajoutées à $rc (ouvre un nouveau terminal ou : source ~/.zshrc)"
