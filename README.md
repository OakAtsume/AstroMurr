<p align="center">
  <img src="docs/kitty logo.png" alt="My lovely Logo" width="750"/>
</p>

<p>
Welcome to the AstroMurr Project! This Ruby-based project is designed to simplify the deployment of Rogue Access Points for out-field testing purposes. Whether you are a network administrator, security professional, or researcher, AstroMurr aims to provide you with a streamlined toolset to test and evaluate the security of wireless networks and devices abroad.
</p>

> Disclaimer: This project is intended for educational and ethical testing purposes only. Unauthorized deployment of Rogue Access Points can be illegal and unethical. Always ensure you have proper authorization and follow the law when conducting any wireless network testing.

## Table of Contents
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Getting Started
### Prerequisites
- [Ruby](https://www.ruby-lang.org/en/downloads/) (>= 2.6.3)
- [Bundler](https://bundler.io/) (>= 2.0.2)
- [Hostapd](https://w1.fi/hostapd/) (>= 2.9)
- [Dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) (>= 2.80)
- Iwconfig
- Ifconfig
- A Linux-based operating system (tested on Debian 10)

### Installation
1. Clone the repository
```sh
git clone https://github.com/OakAtsume/AstroMurr.git
```
2. Install the required gems
```sh
bundle install
```
3. Run the setup script (optional)
```sh
chmod +x setup.sh
./setup.sh
```
4. Run the application
```sh
bundle exec ruby astromurr.rb <options>
```

> Astromurr will bind on ports 53 (DNS), 67 (DHCP), and 80 (HTTP) by default. Ensure these ports are not in use by other services before running Astromurr.


## Usage
### Options
```sh
# Example usage
ruby astromurr.rb wlan1 "Hello World WiFi" 11
# Example usage (with wpa2)
ruby astromurr.rb wlan1 "Hello World WiFi" 11 MyStrongPassword
```
| Option | Description |
| ------ | ----------- |
| Interface | The wireless interface to use for the Rogue Access Point. |
| SSID | The SSID to broadcast for the Rogue Access Point. |
| Channel | The channel to broadcast the Rogue Access Point on (Only 2.4 is currently supported). |
| Password | The password to use for the Rogue Access Point (Optional). |

## Troubleshooting
### Common Issues
- Ensure you are running the application as root.
- Ensure you have the required dependencies installed.
- Ensure you don't have task's running on ports 53, 67, or 80.
- Ensure you killed wpa_supplicant, NetworkManager,dhcpcd, and any other network services. (These can interfere with the Rogue Access Point)


## License
Distributed under the MIT License. See [LICENSE.md](LICENSE.md) for more information.

