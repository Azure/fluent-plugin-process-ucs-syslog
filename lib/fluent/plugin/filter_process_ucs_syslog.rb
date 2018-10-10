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

    @@eventRegex = /%UCSM-\d-([A-Z_]+)/

    @@linkDownMnemonic = "link-down"
    @@faultClearedSeverity = "cleared"

    # Example: [F0283][major][link-down][sys/chassis-4/blade-3/fabric-B/path-3/vc-1488]
    @@tagesRegex = /\[[\w]+\]\[([\w]+)\]\[([-\w]+)\]\[([-\/\w]+)\]/
    @@restartAdaptorRegex = /Adapter (\d)\/(\d)\/\d restarted/

    @@bladeRegex = /sys\/chassis-(\d)\/blade-(\d)/
    @@stageRegex = /\[FSM:(\w+)\]/

    @@bootEvent = "boot"
    @@softShutdownEvent = "soft shutdown"
    @@hardShutdownEvent = "hard shutdown"
    @@externalRestartEvent = "restart"
    @@internalRestartEvent = "internal restart"

    @@etcdHostname = "etcd"
    @@etcdPort = 2379

    def configure(conf)
      super
    end

    def filter(tag, time, record)

      record["machineId"] = ""
      record["event"] = ""
      record["stage"] = ""
      record["type"] = ""
      record["severity"] = ""
      record["mnemonic"] = ""
      record["device"] = ""
      record["error"] = ""

      fullUsername = "#{domain}\\#{username}"
      if !record["message"].include? fullUsername
        # Filter out usernames
        record["message"] = record["message"].gsub(/\\[-\w.]+/, "")
      end

      # Append machine id if found
      determineMachineId(record, @@bladeRegex)

      # Determine syslog type
      splitMessage = record["message"].split(": ")
      if splitMessage[2] !~ @@eventRegex
        # Did not recognize message, do nothing
        return record
      end

      syslogType = splitMessage[2][@@eventRegex, 1]
      if syslogType == "EVENT"
        processEvent(record)
      elsif syslogType == "AUDIT"
        processAudit(record)
      else
        processFaults(record)
      end

      updateEtcd(record)

      return record
    end

    def processEvent(record)
      record["type"] = "event"
      record["severity"] = "info"

      message = record["message"]

      event = determineEvent(message)
      if !event.nil?
        record["event"] = event
      end

      stage = determineStage(message)
      if !stage.nil?
        record["stage"] = stage
      end

      # Internal restarts are special as UCS does not fully detect them
      if event == @@internalRestartEvent
        record["stage"] = "begin"
        determineMachineId(record, @@restartAdaptorRegex)
      end
    end

    def processAudit(record)
      record["type"] = "audit"
      record["severity"] = "info"
      # We currently don't do anything with audit messages
    end

    def processFaults(record)
      message = record["message"]
      
      record["type"] = "fault"
      record["severity"] = message[@@tagesRegex, 1]
      record["mnemonic"] = message[@@tagesRegex, 2]
      record["device"] = message[@@tagesRegex, 3]

      # Check if it is an internal restart
      determineInternalReboot(record)
    end

    def determineInternalReboot(record)
      if record["severity"] == @@faultClearedSeverity and record["mnemonic"] == @@linkDownMnemonic
        # Check if there are any more faults, if not, reboot is complete
        message = record["message"]
        chassisNumber = message[@@bladeRegex,1]
        bladeNumber = message[@@bladeRegex,2]

        response = getFaults(record[ucsHostNameKey], chassisNumber, bladeNumber, @@linkDownMnemonic, @@faultClearedSeverity, 1)
        numberOfFaults = response.scan(/<faultInst/).length

        if numberOfFaults <= 0
          record["stage"] = "end"
          record["event"] = @@internalRestartEvent
        end
      end
    end

    def determineEvent(message)
      case message
        when /Power-on/
          event = @@bootEvent
        when /Soft shutdown/
          event = @@softShutdownEvent
        when /Hard shutdown/
          event = @@hardShutdownEvent
        when /Power-cycle/
          event = @@externalRestartEvent
        when @@restartAdaptorRegex
          event = @@internalRestartEvent
      end
      event
    end

    def determineStage(message)
      if message !~ @@stageRegex
        return nil
      end
      message[@@stageRegex,1].downcase
    end

    def getFaults(host, chassisNumber, bladeNumber, cause, severity, retries)
      queryBody = "<configResolveClass 
          cookie=\"%{token}\" 
          inHierarchical=\"false\" 
          classId=\"faultInst\">
          <inFilter>
          <and>
            <eq class=\"faultInst\" 
              property=\"cause\" 
              value=\"#{cause}\" />
            <wcard class=\"faultInst\" 
              property=\"dn\" 
              value=\"sys/chassis-#{chassisNumber}/blade-#{bladeNumber}\" />
            <ne class=\"faultInst\" 
              property=\"severity\" 
              value=\"#{severity}\" />
          </and>
          </inFilter>
      </configResolveClass>"
      response = getUcsWithRetry(host, queryBody, 1)
      return response
    end

    # Use Regex to determine chassis and blade number from message
    def determineMachineId(record, regex)
      message = record["message"]
      if message !~ regex
        return
      end

      chassisNumber = message[regex,1]
      bladeNumber = message[regex,2]

      begin
        serviceProfile = getServiceProfile(record[ucsHostNameKey], chassisNumber, bladeNumber, 1)
      rescue SecurityError => se
        record["error"] += "Error getting service profile: #{se.message}"
      end

      if !serviceProfile.to_s.empty?
        record["machineId"] = "Cisco_UCS:#{coloregion}:#{serviceProfile}"
      end
    end

    def getServiceProfile(host, chassisNumber, bladeNumber, retries)
      queryBody = "<configResolveDn cookie=\"%{token}\" dn=\"sys/chassis-#{chassisNumber}/blade-#{bladeNumber}\"></configResolveDn>"
      response = getUcsWithRetry(host, queryBody, 1)
      return response[/assignedToDn="([\w\/-]+)"/,1]
    end

    def getUcsWithRetry(host, queryBody, retries)
      if retries > 5
        log.error "Unable to login to UCS"
        raise SecurityError, "Unable to login to UCS"
      end

      token = getToken(host)

      response = callUcsApi(host, queryBody % {token: token})
      errorCode = response[/errorCode="(\d+)"/,1]
      
      if !errorCode.to_s.empty?
        log.info "login failed, retry ", retries
        File.delete(@@tokenFile)
        response = getUcsWithRetry(host, queryBody, retries + 1)
      end

      return response
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
      token = response[/outCookie="([\w\/-]+)"/,1]

      File.open(@@tokenFile, "w") do |f|
        f.write(token)
      end

      return token
    end

    def updateEtcd(record)
      sourceIp = record[ucsHostNameKey]

      uri = URI.parse("http://#{@@etcdHostname}:#{@@etcdPort}/v2/keys/#{sourceIp}")
      request = Net::HTTP::Put.new(uri)

      req_options = {
        use_ssl: uri.scheme == "https",
      }

      begin
        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
          http.request(request)
        end

        if !response.kind_of? Net::HTTPSuccess
          log.error "Error updating etcd: Error code: #{response.code} Response: #{response.value}"
          record["error"] += "Error updating etcd: Error code: #{response.code} Response: #{response.value}"
        end
      rescue SocketError => se
        log.error "Error updating etcd: SocketError: #{se.message}"
        record["error"] += "Error updating etcd: SocketError: #{se.message}"
      end
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
