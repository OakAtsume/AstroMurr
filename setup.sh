#!/bin/bash
# Shitty script to check if all dependencies are installed.
commands=(
	ifconfig
	iwconfig
	hostapd
	dnsmasq
	bundler
	ruby
	gem
)

for command in "${commands[@]}"
do
	if ! command -v "$command" &> /dev/null
	then
		echo "> ${command} : NOT FOUND"
		exit 1
	else
		echo "${command} : OK"
	fi
done

echo "All dependencies are installed"
exit 0