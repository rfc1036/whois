_whois_query() {
	"$1" -q "$2" 2>/dev/null | while read -r item _; do
		[[ $item == %* ]] && continue
		printf "%s\n" "${item%%:*}"
	done
}

_whois_hosts() {
	# _known_hosts_real from github.com/scop/bash-completion if available
	if declare -f _known_hosts_real &>/dev/null; then
		_known_hosts_real -- "$1"
		return 0
	fi
	COMPREPLY=($(compgen -A hostname -- "$1"))
}

_whois() {

	case $3 in
	--help | --version | -p | --port | -i)
		return 0
		;;
	-h | --host)
		_whois_hosts "$2"
		return 0
		;;
	-T | -t | -v)
		[[ ${_whois_types-} ]] ||
			_whois_types=" $(_whois_query "$1" types)"
		COMPREPLY=($(compgen -W '$_whois_types' -- "$2"))
		return 0
		;;
	-s | -g)
		[[ ${_whois_sources-} ]] ||
			_whois_sources=" $(_whois_query "$1" sources)"
		COMPREPLY=($(compgen -W '$_whois_sources' -- "$2"))
		if [[ $3 == -g ]]; then
			[[ ${#COMPREPLY[*]} -eq 1 ]] && COMPREPLY[0]+=:
			compopt -o nospace
		fi
		return 0
		;;
	-q)
		COMPREPLY=($(compgen -W 'version sources types' -- "$2"))
		return 0
		;;
	esac

	if [[ $2 == -* ]]; then
		COMPREPLY=($(compgen -W '
			-h --host
			-p --port
			-I
			-H
			--verbose
			--no-recursion
			--help
			--version
			-l
			-L
			-m
			-M
			-c
			-x
			-b
			-B
			-G
			-d
			-i
			-T
			-K
			-r
			-R
			-a
			-s
			-g
			-t
			-v
			-q
		' -- "$2"))
		return 0
	fi

	_whois_hosts "$2"

} && complete -F _whois whois
