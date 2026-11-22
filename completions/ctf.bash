# Complétion bash pour ctf.
_ctf_complete() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$(ctf _complete commands 2>/dev/null)" -- "$cur") )
    return
  fi
  case "${COMP_WORDS[1]}" in
    use)  COMPREPLY=( $(compgen -W "$(ctf _complete challenges 2>/dev/null)" -- "$cur") ) ;;
    vpn)  COMPREPLY=( $(compgen -W "$(ctf _complete vpn 2>/dev/null)" -- "$cur") ) ;;
  esac
}
complete -F _ctf_complete ctf
