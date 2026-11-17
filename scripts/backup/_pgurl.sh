# shellcheck shell=bash
# Sourced by the backup scripts. Keeps a password out of argv (visible in `ps` and /proc).
#
# libpq reads a password from a connection URL only if the URL is passed on the command
# line, so: move the password out of DATABASE_URL into PGPASSWORD (an environment variable,
# inherited by the client, or by `docker run -e PGPASSWORD` which takes the name only),
# and leave a URL without it in DATABASE_URL.
falak_split_url_password() {
  local url="${DATABASE_URL:-}"
  [ -n "$url" ] || return 0
  case "$url" in
    *[?\&]password=*)
      echo "Error: put the password in PGPASSWORD or the URL's userinfo, not in a ?password= parameter (it would show in the process list)." >&2
      return 1 ;;
  esac
  local scheme="${url%%://*}" rest="${url#*://}"
  [ "$rest" != "$url" ] || return 0
  local authority="${rest%%[/?]*}"
  local tail="${rest#"$authority"}"
  case "$authority" in *@*) ;; *) return 0 ;; esac
  local userinfo="${authority%@*}" hostpart="${authority##*@}"
  case "$userinfo" in *:*) ;; *) return 0 ;; esac
  local user="${userinfo%%:*}" pw="${userinfo#*:}"
  # Percent-decode: libpq wants the raw password in PGPASSWORD.
  PGPASSWORD="$(printf '%b' "${pw//%/\\x}")"
  export PGPASSWORD
  DATABASE_URL="${scheme}://${user}@${hostpart}${tail}"
  export DATABASE_URL
}
