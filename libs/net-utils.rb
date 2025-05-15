class NetUtils
  def initialize
  end

  def interfaceExist?(interface)
    return File.exist?("/sys/class/net/#{interface}")
  end

  def is5ghz?(channel)
    case channel.to_i
    when 1..14
      false
    when 36..64, 100..144, 149..165
      true
    else
      nil
    end
  end
end