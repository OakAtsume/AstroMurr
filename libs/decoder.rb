# frozen_string_literal: true

require('json')
require('net/http')
require('digest')

$Settings = {
  'Port' => 80,
  'SSL-Port' => 443,
  'SSL-Key' => 'src/server.key',
  'SSL-Cert' => 'src/server.crt',
  'Verify-SSL' => false,
  'FireLock' => 'src/firelock.json',
  'MaxRead' => 1024, # Buffer
  'RawFilesExts' => %w[
    ico
    jpg
    jpeg
    png
    gif
    svg
    webp
  ],
  'IdIps' => [
    '0.0.0.0',
    '127.0.0.1',
    'localhost'
  ]
}

COLORA = {
  :reset     => "\e[0m",
  :bold      => "\e[1m",
  :italic    => "\e[3m",
  :underline => "\e[4m",
  :blink     => "\e[5m",
  :reverse   => "\e[7m",
  :hidden    => "\e[8m"
}


class Log4Bot
  def initialize(time)
    @timeformat = time
    @logtext = Time.now.strftime(@timeformat).to_s
  end

  def log(message)
    print "\e[38;2;0;211;0m[#{Time.now.strftime(@timeformat)}]:\e[0m #{message}\e[0m\n"
    # File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def error(message)
    print "\e[38;2;255;0;0m[#{Time.now.strftime(@timeformat)}]-Error:\e[0m #{message}\e[0m\n"
    # File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def warn(message)
    print "\e[38;2;200;0;0m[#{Time.now.strftime(@timeformat)}]-Warn:\e[0m #{message}\e[0m\n"
    # File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def info(message)
    print "\e[38;2;0;0;255m[#{Time.now.strftime(@timeformat)}]-Info:\e[0m #{message}\e[0m\n"
    # File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def debug(message)
    print "\e[38;2;255;255;0m[#{Time.now.strftime(@timeformat)}]-Debug:\e[0m #{message}\e[0m\n"
    # File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def dns(message)
    print "\e[38;2;255;0;255mDNS:\e[0m #{message}\e[0m\n"
    # File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def hostapd(message)
    print "\e[38;2;255;0;255mWireless:\e[0m #{message}\e[0m\n"
    # File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def dhcp(message)
    print "\e[38;2;255;0;255mDHCP:\e[0m #{message}\e[0m\n"
    # File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def http(message)
    print "\e[38;2;255;0;255mHTTP:\e[0m #{message}\e[0m\n"
    # File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def showlogo()
    logo = File.read('libs/logo.txt')
    # Generate a random color
    color = "\e[38;2;#{Random.rand(0..255)};#{Random.rand(0..255)};#{Random.rand(0..255)}m"
    # Print the logo
    logo = logo.split("\n")
    logo.each do |line|
      line.gsub!('[Project-Name]', 'Astromurr')
      line.gsub!('[Version]', 'v2.0.0 - Semi-Stable')
      print "#{color}#{line}\n"
      color = "\e[38;2;#{Random.rand(0..255)};#{Random.rand(0..255)};#{Random.rand(0..255)}m"
    end
    print("\e[0m")
  end
end

class Decoder
  def decode(input, ip)
    output = {}
    parse = input.split("\r\n\r\n")[0].split("\r\n")
    output['Method'] = parse[0].split(' ')[0]
    output['Path'] = parse[0].split(' ')[1]
    output['Protocol'] = parse[0].split(' ')[2]
    output['Headers'] = {}
    parse[1..].each do |header|
      output['Headers'][header.split(': ')[0]] = header.split(': ')[1]
    end
    output['Data'] = parseData(input.split("\r\n\r\n")[1]) unless input.split("\r\n\r\n")[1].nil?
    output['Cookies'] = parseCookies(output['Headers']['Cookie']) unless output['Headers']['Cookie'].nil?
    output['IP'] = if $Settings['IdIps'].include?(ip.to_s)
                     extractIp(output['Headers'], ip)
                   else
                     ip
                   end
    output['Raw?'] = false
    output['Ext'] = ''
    output['Path'] = output['Path'].gsub(%r{(?:\.{2}(?:/|\\)|/{2,}|\\{2,}|\0|^\.|/0)}, '/')
    output['Path'] = '/index.html' if output['Path'] == '/'
    ext = output['Path'].split('.').last
    output['Ext'] = ext
    if $Settings['RawFilesExts'].include?(ext)
      output['Raw?'] = true
    elsif ext == 'svg'
      output['Ext'] = 'svg+xml'
    end
    output
  end

  def parseData(data)
    output = {}
    data.split('&').each do |item|
      output[item.split('=')[0]] = item.split('=')[1]
    end
    output
  end

  def parseCookie(data)
    output = {}
    data.split('; ').each do |item|
      output[item.split('=')[0]] = item.split('=')[1]
    end
    output
  end

  def extractIp(headers, ip)
    if headers['X-Forwarded-For'].nil?
      ip
    else
      headers['X-Forwarded-For'].split(', ')[0]
    end
  end

  def genResponse(code, headers, data)
    out = ''
    out += "HTTP/1.1 #{code}\r\n"
    # out += "X-Content-Type-Options: nosniff\r\n"
    # out += "X-Download-Options: noopen\r\n"
    # out += "X-Frame-Options: SAMEORIGIN\r\n"
    # out += "X-Permitted-Cross-Domain-Policies: none\r\n"
    # out += "X-XSS-Protection: 1; mode=block\r\n"
    out += "Content-Type: #{headers}\r\n"
    out += "Content-Length: #{data.size}\r\n"
    out += "Connection: close\r\n"
    out += "\r\n"
    out += data
    out
  end

  def genRedir(url)
    out = ''
    out += "HTTP/1.1 302 Found\r\n"
    out += "Location: #{url}\r\n"
    out += "Connection: close\r\n"
    out += "\r\n"
    out
  end
end

class PacketParser
end
