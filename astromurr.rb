require_relative("libs/decoder")
require_relative("libs/net-utils")
require("socket")
require("json")

logs = Log4Bot.new("%H:%M:%S")
netutils = NetUtils.new()

# logs.showlogo
# Basic Arguments
arguments = {
  "interface" => nil,
  "essid" => nil,
  "channel" => nil,
  "password" => nil,
  "mode" => 0,
  "internet" => nil,
  "tap" => false,
  "mana" => false,
  "mana-full" => false
}
ARGV.each do |arg|
  if arg.start_with?("--")
    arg = arg.split("=")
    if arg[1] == "true"
      arg[1] = true
    elsif arg[1] == "false"
      arg[1] = false
    end
    arguments[arg[0].gsub("--", "")] = arg[1]
  end
end
if arguments["mode"].to_s =~ /^\d+$/
  arguments["mode"] = arguments["mode"].to_i
elsif arguments["channel"].to_s =~ /^\d+$/
  arguments["channel"] = arguments["channel"].to_i
else
  logs.error("Channel / Mode must be an integer")
  exit 1
end


ARGV.clear # Clear the arguments so we don't get any errors.
puts arguments

if arguments["interface"].nil? || arguments["essid"].nil? || arguments["channel"].nil? || arguments["mode"] > 2
  logs.error("#{COLORA[:bold]}Invalid arguments.#{COLORA[:reset]}")
  logs.info("#{COLORA[:underline]}Required Arguments#{COLORA[:reset]}: --interface, --essid, --channel, --mode")
  logs.info("Example: #{COLORA[:italic]}--interface=wlan0 --essid=\"Free WiFi\" --channel=11 --mode=0#{COLORA[:reset]}")
  logs.info("|#{' ' * 29}#{COLORA[:bold]}HELP#{COLORA[:reset]}#{' ' * 29}|")
  logs.info("#{'-' * 64}")

  logs.info("#{COLORA[:bold]}Basic Required Arguments#{COLORA[:reset]}")
  logs.info("  #{COLORA[:bold]}interface#{COLORA[:reset]} : The wireless interface to use.")
  logs.info("  #{COLORA[:bold]}essid#{COLORA[:reset]}     : The #{COLORA[:italic]}name#{COLORA[:reset]} of the fake wireless network.")
  logs.info("  #{COLORA[:bold]}channel#{COLORA[:reset]}   : The WiFi channel (must be supported by your adapter).")
  logs.info("  #{COLORA[:bold]}mode#{COLORA[:reset]}      : Operating mode (see below).")

  logs.info("#{COLORA[:bold]}Optional Arguments#{COLORA[:reset]}")
  logs.info("  #{COLORA[:bold]}internet#{COLORA[:reset]}  : Outbound interface for relaying internet (optional).")
  # logs.info("  #{COLORA[:bold]}tap#{COLORA[:reset]}       : Create a TAP interface (requires 'internet').")
  logs.info("  #{COLORA[:bold]}mana#{COLORA[:reset]}      : Enable HostAPd-mana's attack features.")
  logs.info("  #{COLORA[:bold]}mana-full#{COLORA[:reset]} : Use aggressive MANA mode.")
  logs.info("  #{COLORA[:bold]}dns-hosts#{COLORA[:reset]} : DNS sinkhole hosts file for mode 3 (sink all if omitted).")

  logs.info("#{COLORA[:bold]}Interaction Modes#{COLORA[:reset]}")
  logs.info("  #{COLORA[:bold]}0#{COLORA[:reset]} : Open Access Point — clients can connect, get IP, optional internet.")
  logs.info("  #{COLORA[:bold]}1#{COLORA[:reset]} : Fake Google — captive portal phishing via DNS sinkhole (no internet).")
  logs.info("  #{COLORA[:bold]}2#{COLORA[:reset]} : DNS Sinkhole — acts as AP with DNS trap (sinks all if no host file).")
end

hostapdConfig = []
dnsmasqConfig = []
# 
dnsLog = "/tmp/#{Random.rand(1000..9999)}.log"
hostLog = "/tmp/#{Random.rand(1000..9999)}.log"
# 
dhcpConf = "/tmp/#{Random.rand(1000..9999)}.conf"
hostConf = "/tmp/#{Random.rand(1000..9999)}.conf"

hostThreads = nil
dhcpThreads = nil
dhcpHandler = nil
hostHandler = nil

trap("INT") do
  logs.warn("Caught SIGINT, stopping...")

  system("killall hostapd dnsmasq hostapd-mana")
  # Delete the files
  # system("rm #{hostLog} #{dnsLog} #{hostConf} #{dhcpConf}")
  [hostLog, dnsLog, hostConf, dhcpConf].each do |f|
    File.delete(f) if File.exist?(f)
  end

  system("iwconfig #{arguments["interface"]} mode managed")

  hostThreads.kill
  dhcpThreads.kill
  Process.kill("SIGKILL", Process.pid)
  exit
end


# trap("EXIT") do
#   logs.warn("Caught SIGEXIT, stopping...")
#   system("killall hostapd dnsmasq hostapd-mana")
#   # Delete the files
#   [hostLog, dnsLog, hostConf, dhcpConf].each do |f|
#     File.delete(f) if File.exist?(f)
#   end

#   system("iwconfig #{arguments["interface"]} mode managed")

#   hostThreads.kill
#   dhcpThreads.kill
#   Process.kill("SIGKILL", Process.pid)
#   exit
# end



# Check user's paramns aren't bogus.
if !netutils.interfaceExist?(arguments["interface"])
  logs.error("Invalid interface given #{arguments["internet"]}... (not found)")
  exit 1
elsif !arguments["internet"].nil? && (!netutils.interfaceExist?(arguments["internet"]))
  logs.error("Invalid Internet interface given #{arguments["internet"]}... (not found)")
  exit 1
end


hostapdConfig.push("interface=#{arguments["interface"]}")
hostapdConfig.push("driver=nl80211")
hostapdConfig.push("ssid=#{arguments["essid"]}")
hostapdConfig.push("channel=#{arguments["channel"]}")

# Generate the configs
if netutils.is5ghz?(arguments["channel"]).nil?
  logs.error("Invalid Channel; 1 -> 14 2.4GHz to 36 -> 165 5Ghz")
  exit 1
end

if netutils.is5ghz?(arguments["channel"])
  logs.warn("Be sure that your WiFi card can support 5ghz!!")
  hostapdConfig.push("hw_mode=a")
else
  hostapdConfig.push("hw_mode=g")
end

# Check for MANA stuff
if arguments["mana"]
  hostapdConfig.push("enable_mana=1")

end
if arguments["mana-full"]
  hostapdConfig.push("mana_loud=1")
end



# Other stuff here lol
hostapdConfig.push("country_code=US")
hostapdConfig.push("macaddr_acl=0")
hostapdConfig.push("ignore_broadcast_ssid=0")
hostapdConfig.push("ieee80211d=1")
hostapdConfig.push("ieee80211n=1")
hostapdConfig.push("ieee80211ac=1")

# For WPA 2 (not in use lol) #
# f.puts("auth_algs=1")
# f.puts("wpa=2")
# f.puts("wpa_passphrase=#{Password}")
# f.puts("wpa_key_mgmt=WPA-PSK")
# f.puts("wpa_pairwise=TKIP")
# f.puts("rsn_pairwise=CCMP")


# #DEBUG
# puts("Hostapd config")
# puts hostapdConfig.join("\n")
# #DEBUG





# Configure interface(s)
if system("iwconfig #{arguments["interface"]} mode managed 2> /dev/null")
  logs.info("Configured #{arguments["interface"]} to #{COLORA[:bold]}managed#{COLORA[:end]} mode")
else
  logs.error("Failed to set #{arguments["interface"]} to managed mode.")
  exit 1
end

# Set the interface's IP n stuff
if system("ifconfig #{arguments["interface"]} 10.0.1.1 netmask 255.255.255.0 2> /dev/null")
  logs.info("Set #{arguments["interface"]} to #{COLORA[:bold]}10.0.1.1#{COLORA[:end]}")
else
  logs.error("Failed to set #{arguments["interface"]}'s IP address")
  exit 1
end


dnsmasqConfig.push("interface=#{arguments["interface"]}")
dnsmasqConfig.push("dhcp-authoritative")
dnsmasqConfig.push("log-dhcp")
dnsmasqConfig.push("log-queries")
dnsmasqConfig.push("log-facility=#{dnsLog}")
dnsmasqConfig.push("bind-interfaces")
dnsmasqConfig.push("bogus-priv")
dnsmasqConfig.push("dhcp-range=10.0.1.2,10.0.1.100,12h")
dnsmasqConfig.push("server=1.1.1.1")



case arguments["mode"]
when 0
  logs.info("Mode 0 selected: Open Access Point")
  
  dnsmasqConfig.push("dhcp-option=3,10.0.1.1")
  dnsmasqConfig.push("dhcp-option=6,1.1.1.1") # DNS server

  if arguments["internet"]
    logs.info("Enabling IP forwarding and NAT via #{arguments["internet"]}")
    begin
      system("sysctl -w net.ipv4.ip_forward=1")
      system("iptables --flush")
      system("iptables --table nat --flush")
      system("iptables --delete-chain")
      system("iptables --table nat --delete-chain")
      system("iptables -t nat -A POSTROUTING -o #{arguments["internet"]} -j MASQUERADE")
      system("iptables -A FORWARD -i #{arguments["internet"]} -o #{arguments["interface"]} -m state --state RELATED,ESTABLISHED -j ACCEPT")
      system("iptables -A FORWARD -i #{arguments["interface"]} -o #{arguments["internet"]} -j ACCEPT")
    rescue => e
      logs.error("Failed to configure NAT:\n#{e}\n#{e.backtrace.join("\n")}")
    end
  end
when 1
  logs.info("Mode 1 selected: Captive Portal / Fake Google")
when 2
  logs.info("Mode 2 selected: DNS Sinkhole")
end

logs.info("DCHP/HOSTAPD to #{dhcpConf} : #{hostConf}")
File.write(dhcpConf, dnsmasqConfig.join("\n"))
File.write(hostConf, hostapdConfig.join("\n"))

hostThreads = Thread.new do 
  File.new(hostLog, "w", 0o644)
  cmd = ""
  if arguments["mana"]
    cmd = "hostapd-mana"
  else
    cmd = "hostapd"
  end

  if system("#{cmd} #{hostConf} > #{hostLog} 2>&1")
    logs.info("Started hostapd on \e[1m#{arguments["interface"]}\e[0m")
  else
    logs.error("Failed to start hostapd on \e[1m#{arguments["interface"]}\e[0m")
    exit 1
  end
end

dhcpThreads = Thread.new do
  File.new(dnsLog, "w", 0o644)
  if system("dnsmasq -C #{dhcpConf} -k")
    logs.info("Started dnsmasq on \e[1m#{arguments["interface"]}\e[0m")
  else
    logs.error("Failed to start dnsmasq on \e[1m#{arguments["interface"]}\e[0m")
    exit 1
  end
end




# hostapdConfig = []
# dnsmasqConfig = []
# # 
# dnsLog = "/tmp/#{Random.rand(1000..9999)}.log"
# hostLog = "/tmp/#{Random.rand(1000..9999)}.log"
# # 
# dhcpConf = "/tmp/#{Random.rand(1000..9999)}.conf"
# hostConf = "/tmp/#{Random.rand(1000..9999)}.conf"


fails = 0

hostLogFile = nil
dnsLogFile = nil
LogThread = Thread.start do
  loop do
    if hostLogFile.nil? || dnsLogFile.nil?
      begin
        hostLogFile = File.open(hostLog, "r")
        dnsLogFile = File.open(dnsLog, "r")
        logs.info("Hooked into \e[1m#{hostLog}\e[0m and \e[1m#{dnsLog}\e[0m")
      rescue Exception => e
        fails += 1
        sleep 0.5
        if fails > 5
          logs.error("Failed to open log files: #{e}")
          exit 1
        end
        retry
      end
    end
    lastestDns = dnsLogFile.read
    lastestHost = hostLogFile.read
    unless lastestDns.nil?
      lastestDns.chomp!
      # Log.debug("DNS: #{lastestDns}") unless lastestDns.empty?
      # next if lastestDns.empty?
      # puts lastestDns if !lastestDns.empty?
      if lastestDns.include?("DHCPACK")
        data = lastestDns.split(" ")
        ip = data[6]
        mac = data[7]
        hostname = if data[8].nil?
            "unknown"
          else
            data[8]
          end
        logs.dhcp("IP:\e[1m#{ip}\e[0m -> \e[1m#{mac}\e[0m (#{hostname})")
      elsif lastestDns.include?("query[")
        data = lastestDns.split(" ")
        hostname = data[5]
        from = data[7]
        logs.dns("\e[1m#{from}\e[0m ---> \e[1m#{hostname}\e[0m \e[38;2;211;211;0m(Query)\e[0m")
      elsif lastestDns.include?("config")
        data = lastestDns.split(" ")
        hostname = data[5]
        from = data[7]
        logs.dns("\e[1m#{from}\e[0m <--- \e[1m#{hostname}\e[0m \e[38;2;100;0;211m(Reply)\e[0m")
      end
    end
    next if lastestHost.nil?

    lastestHost.chomp!
    # Log.debug("HOST: #{lastestHost}") unless lastestHost.empty?
    if lastestHost.include?("AP-STA-CONNECTED")
      data = lastestHost.split(" ")
      mac = data[2]
      logs.hostapd("Client \e[1m#{mac}\e[0m connected")
    elsif lastestHost.include?("AP-STA-DISCONNECTED")
      data = lastestHost.split(" ")
      mac = data[2]
      logs.hostapd("Client \e[1m#{mac}\e[0m disconnected")
    end
  end
end

LogThread.join
