_mkpasswd() {

	case $3 in
	--help | --version | --salt | --rounds | --password-fd | -[hVSRP])
		return 0
		;;
	--method | -m)
		COMPREPLY=($(compgen -W '$(
			LC_ALL=C "$1" --method=help 2>/dev/null |
				while read -r method _; do
					[[ $method == Available ]] ||
						printf "%s\n" "$method"
				done
			)'))
		return 0
		;;
	esac

	if [[ $2 == -* ]]; then
		COMPREPLY=($(compgen -W '
			--method
			-5
			--salt
			--rounds
			--password-fd
			--stdin
			--help
			--version
		' -- "$2"))
		return 0
	fi

} && complete -F _mkpasswd mkpasswd
