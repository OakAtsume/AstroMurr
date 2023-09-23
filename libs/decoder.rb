require('json')
require('net/http')
require('digest')

class Log4Bot
  def initialize(time)
    @timeformat = time
    @logtext = Time.now.strftime(@timeformat).to_s
  end
  def log(message)
    print "\e[38;2;0;211;0m[#{Time.now.strftime(@timeformat)}]:\e[0m #{message}\e[0m\n"
    File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def error(message)
    print "\e[38;2;255;0;0m[#{Time.now.strftime(@timeformat)}]-Error:\e[0m #{message}\e[0m\n"
    File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def warn(message)
    print "\e[38;2;200;0;0m[#{Time.now.strftime(@timeformat)}]-Warn:\e[0m #{message}\e[0m\n"
    File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def info(message)
    print "\e[38;2;0;0;255m[#{Time.now.strftime(@timeformat)}]-Info:\e[0m #{message}\e[0m\n"
    File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end

  def debug(message)
    print "\e[38;2;255;255;0m[#{Time.now.strftime(@timeformat)}]-Debug:\e[0m #{message}\e[0m\n"
    File.open('log.txt', 'a') { |f| f.write("[#{Time.now.strftime(@timeformat)}]: #{message}\n") }
  end
  def Logo
	logo = File.read('libs/logo.txt')
	# Generate a random color
	color = "\e[38;2;#{Random.rand(0..255)};#{Random.rand(0..255)};#{Random.rand(0..255)}m"
	# Print the logo
	logo = logo.split("\n")
	logo.each do |line|
		line.gsub!("[Project-Name]", "Astromurr")
    line.gsub!("[Version]", "v0.1.0")
    print "#{color}#{line}\n"
		color = "\e[38;2;#{Random.rand(0..255)};#{Random.rand(0..255)};#{Random.rand(0..255)}m"
    
  end


  end
end



class Decoder
  def generateNewToken
    # Generate a new token
    random = Random.new
    output = ''
    32.times do
      output += random.rand(0..9).to_s
    end
    output
  end

  def sha256(input)
    Digest::SHA256.hexdigest(input)
  end

  def decode(input, ip)
    output = {}
    # Parse headers #
    parse = input.split("\r\n\r\n")[0].split("\r\n")
    output['Method'] = parse[0].split(' ')[0]
    output['Path'] = parse[0].split(' ')[1]
    output['Protocol'] = parse[0].split(' ')[2]
    output['Headers'] = {}
    parse[1..].each do |header|
      output['Headers'][header.split(': ')[0]] = header.split(': ')[1]
    end
    # Parse data #
    output['Data'] = parseData(input.split("\r\n\r\n")[1]) unless input.split("\r\n\r\n")[1].nil?
    # Parse cookies #
    output['Cookies'] = parseCookies(output['Headers']['Cookie']) unless output['Headers']['Cookie'].nil?
    # Parse IP #
    # If ip seem's like it belongs to a tunnel/reverse-proxy then continue
    output['IP'] = if $Settings['IdIps'].include?(ip.to_s)
                     extractIp(output['Headers'], ip)
                   else
                     ip
                   end
    output['Raw?'] = false
    output['Ext'] = ''
    # Anti-directory traversal #
    output['Path'] = output['Path'].gsub(%r{(?:\.{2}(?:/|\\)|/{2,}|\\{2,}|\0|^\.|/0)}, '/')
    # Auto-Correct #
    # Turn -> / into index.html
    output['Path'] = '/index.html' if output['Path'] == '/'
    # Turn -> /index into /index.html
    output['Path'] = '/index.html' if output['Path'].include?('index')
    # If it contains anything about gen or captive portal stuff, redirect to index.html
    output['Path'] = '/index.html' if output['Path'].include?('gen') || output['Path'].include?('captive')
    # Check if file has an extension
    if output['Path'].include?('.')
      ext = output['Path'].split('.').last
      output['Ext'] = ext
      if $Settings['RawFilesExts'].include?(ext)
        # Assume it's an image.
        # output['Path'] = "#{Paths['imgs']}/#{output['Path']}"

        output['Raw?'] = true
      elsif ext == 'svg'
        # Assume it's an image.
        output['Ext'] = 'svg+xml'

        # Assume it's a stylesheet
        # output['Path'] = "#{Paths['style']}"
        # elsif ext == 'html'
        #   output['Path'] = "#{Paths['data']}"
      end
    end

    output
  end

  def parseData(data)
    # Split key=value pairs by &
    output = {}
    data.split('&').each do |pair|
      output[pair.split('=')[0]] = pair.split('=')[1]
    end
    output
  end

  def parseCookies(cookies)
    # Split key=value pairs by ;
    output = {}
    cookies.split('; ').each do |pair|
      output[pair.split('=')[0]] = pair.split('=')[1]
    end
    output
  end

  def generateResponse(code, headers, data)
    out = ''
    out += "HTTP/1.1 #{code}\r\n"
    out += "X-Content-Type-Options: nosniff\r\n"
    out += "X-Download-Options: noopen\r\n"
    out += "X-Frame-Options: SAMEORIGIN\r\n"
    out += "X-Permitted-Cross-Domain-Policies: none\r\n"
    out += "X-XSS-Protection: 1; mode=block\r\n"
    out += "Content-Type: #{headers}\r\n"

    out += "Content-Length: #{data.size}\r\n"

    out += "Connection: close\r\n"
    out += "\r\n"
    out += data
    out
  end

  def generateRedirect(redirect)
    out = ''
    out += "HTTP/1.1 302 Found\r\n"
    out += "X-Content-Type-Options: nosniff\r\n"
    out += "X-Download-Options: noopen\r\n"
    out += "X-Frame-Options: SAMEORIGIN\r\n"
    out += "X-Permitted-Cross-Domain-Policies: none\r\n"
    out += "X-XSS-Protection: 1; mode=block\r\n"
    out += "Location: #{redirect}\r\n"
    out += "Connection: close\r\n"
    out += "\r\n"
    out
  end

  def extractIp(request, default = '')
    ip = ''
    if request.include?('X-Forwarded-For')
      ip = request['X-Forwarded-For']
    elsif request.include?('X-Real-IP')
      ip = request['X-Real-IP']
    elsif request.include?('Remote-Addr')
      ip = request['Remote-Addr']
    end
    # Regex to check if the IP is valid
    ip = default if ip.empty?
    unless ip =~ /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
      return "#{ip}"
    end

    ip
  end
end
