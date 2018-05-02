require 'fluent/plugin/filter'

module Fluent::Plugin
  class ProcessUcsSyslog < Filter
    Fluent::Plugin.register_filter('process_ucs_syslog', self)

    config_param :ucsHostNameKey, :string
    config_param :coloregion, :string
    config_param :domain, :string
    config_param :username, :string
    config_param :passwordFile, :string

    @@tokenFile = "/tmp/token"

    @@bladeRegex = /sys\/chassis-\d\/blade-\d/
    @@stageRegex = /\[FSM:(\w+)\]/

    def configure(conf)
      super
    end

    def filter(tag, time, record)

      message = record["message"]
      record["event"] = ""
      record["stage"] = ""
      record["machineId"] = ""

      event = determineEvent(message)
      if !event.nil?
        record["event"] = event
      end

      stage = determineStage(message)
      if !stage.nil?
        record["stage"] = stage
      end

      # Need to filter out usernames
      record["message"] = record["message"].gsub(/\\[-\w.]+/, "")

      if message !~ @@bladeRegex
        return record
      end

      dn = message[@@bladeRegex,0]

      serviceProfile = getServiceProfile(record[ucsHostNameKey], dn, 1)
      if serviceProfile != ""
        record["machineId"] = "Cisco_UCS:#{coloregion}:#{serviceProfile}"
      end

      record
    end

    def determineEvent(message)
      case message
        when /Power-on/
          event = "Boot"
        when /Soft shutdown/
          event = "Soft Shutdown"
        when /Hard shutdown/
          event = "Hard Shutdown"
        when /Power-cycle/
          event = "Restart"
      end
      event
    end

    def determineStage(message)
      if message !~ @@stageRegex
        return nil
      end
      message[@@stageRegex,1].downcase
    end

    def getServiceProfile(host, dn, retries)
      if retries > 5
        log.error "unable to login to UCS to get service profile"
        return ""
      end

      token = getToken(host)

      queryBody = "<configResolveDn cookie=\"%s\" dn=\"%s\"></configResolveDn>" % [token, dn]
      response = callUcsApi(host, queryBody)
      profile = response[/assignedToDn="([\d\w\/-]+)"/,1]
      errorCode = response[/errorCode="(\d+)"/,1]
      
      if !errorCode.to_s.empty?
        log.info "login failed, retry ", retries
        File.delete(@@tokenFile)
        profile = getServiceProfile(host, dn, retries + 1)
      end

      return profile
    end

    def getToken(host)
      if File.exist?(@@tokenFile)
        token = File.read(@@tokenFile)
        return token
      end

      password = getPassword()
      fullUsername = domain + "\\" + username
      loginBody = "<aaaLogin inName=\"#{fullUsername}\" inPassword=\"#{password}\"></aaaLogin>"
      response = callUcsApi(host, loginBody)
      token = response[/outCookie="([\d\w\/-]+)"/,1]

      File.open(@@tokenFile, "w") do |f|
        f.write(token)
      end

      return token
    end

    def callUcsApi(host, body)
      uri = URI.parse("https://#{host}/nuova")
      header = {'Content-Type': 'text/xml'}

      https = Net::HTTP.new(uri.host, uri.port)
      https.use_ssl = true
      https.verify_mode = OpenSSL::SSL::VERIFY_NONE
      request = Net::HTTP::Post.new(uri.request_uri, header)
      request.body = body

      response = https.request(request)
      response.body
    end

    def getPassword()
      File.read(passwordFile).strip
    end
  end
end