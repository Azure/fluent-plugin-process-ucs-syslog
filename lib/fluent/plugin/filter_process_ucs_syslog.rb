require 'fluent/plugin/filter'

module Fluent::Plugin
  class ProcessUcsSyslog < Filter
    Fluent::Plugin.register_filter('process_ucs_syslog', self)

    config_param :ucsHostNameKey, :string
    config_param :coloregion, :string
    config_param :username, :string
    config_param :passwordFile, :string

    # Define an optional configuration parameter for 'domain' with no default
    config_param :domain, :string, default: nil

    @@tokenFile = "/tmp/token"
    # the epochs have a unit of seconds
    @@refreshTokenAfterXSeconds = 60*60 # since tokens expire at 2 hours, refresh after 1 hour

    @@eventRegex = /%UCSM-\d-([A-Z_]+)/

    @@linkDownMnemonic = "link-down"
    @@faultClearedSeverity = "cleared"

    # Example: [F0283][major][link-down][sys/chassis-4/blade-3/fabric-B/path-3/vc-1488]
    @@tagesRegex = /\[[\w]+\]\[([\w]+)\]\[([-\w]+)\]\[([-\/\w]+)\]/
    @@restartAdaptorRegex = /Adapter (\d)\/(\d)\/\d restarted/

    @@bladeRegex = /sys\/chassis-([\d]+)\/blade-([\d]+)/
    @@stageRegex = /\[FSM:(\w+)\]/

    @@bootEvent = "boot"
    @@softShutdownEvent = "soft shutdown"
    @@hardShutdownEvent = "hard shutdown"
    @@externalRestartEvent = "restart"
    @@internalRestartEvent = "internal restart"

    def configure(conf)
      super
      if @domain.nil?
        log.info("Domain not specified in that scenerio")
      else
        log.info("Using domain: #{@domain}")
      end
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

      # Call the function to get the full username
      fullUsername = get_full_username(@domain, @username)
      
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
        log.info "Returning record as-is: did not recognize message #{record["message"]}; looking for regex in message: #{@@eventRegex}"
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
        log.info "Returning record without BareMetalMachineID info: message #{message} did not match regex #{regex}"
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
        log.error "Max retries calling UCS reached"
        raise SecurityError, "Max retries calling UCS reached"
      end

      token = getToken(host)
      response = callUcsApi(host, queryBody % {token: token})
      errorCode = response[/errorCode="(\d+)"/,1]

      if !errorCode.to_s.empty?
        log.info "Calling UCS API failed, retry #{retries}; response: #{response.inspect}"

        if File.exist?(@@tokenFile)
          logoutToken(host, File.read(@@tokenFile))
        end

        File.delete(@@tokenFile)
        response = getUcsWithRetry(host, queryBody, retries + 1)
      end

      return response
    end
    
    def logoutToken(host, token)
      logoutBody = "<aaaLogout inCookie=\"#{token}\" />"
      log.info "logging out with body ", logoutBody

      response = callUcsApi(host, logoutBody)
      log.info "logging out response ", response
    end

    def getToken(host)
      tokenResponse = ""

      # Call the function to get the full username
      fullUsername = get_full_username(@domain, @username)

      password = getPassword()

      if File.exist?(@@tokenFile)
        # Example format: 1604697553/058fb963-cf5b-40fc-a1c0-5d713ec2cbad, where 1604697553 is the epoch when the token was generated
        token = File.read(@@tokenFile).strip

        if token == ""
          log.info "File does not contain a token; logging into UCS"
          loginBody = "<aaaLogin inName=\"#{fullUsername}\" inPassword=\"#{password}\"></aaaLogin>"
          tokenResponse = callUcsApi(host, loginBody)
        else
          tokenEpochStr = token[/(\d+)\/.+/,1]
          age = Time.now.to_i - tokenEpochStr.to_i
          if age <= @@refreshTokenAfterXSeconds
            log.info "Existing token will continue being used (not older than #{@@refreshTokenAfterXSeconds} seconds)"
            return token
          else
            log.info "Existing token will be refreshed, as it is #{age} seconds old"

            # aaaRefresh request body documented here: https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/e/api/guide/b_cimc_api_book/b_cimc_api_book_chapter_010.pdf
            # response will have a new token, with a new epoch
            refreshBody = "<aaaRefresh cookie=\"#{token}\" inCookie=\"#{token}\" inName=\"#{fullUsername}\" inPassword=\"#{password}\"></aaaRefresh>"
            # example response: <aaaRefresh cookie="1604697553/058fb963-cf5b-40fc-a1c0-5d713ec2cbad" response="yes" outCookie="1604699567/27696198-dd82-444d-98c6-0e36a3f927cd" outRefreshPeriod="600" outPriv="admin,read-only" outDomains="" outChannel="noencssl" outEvtChannel="noencssl" outName="ucs-HANATDIT\sa-hanarp"> </aaaRefresh>
            # once the new token is generated, making calls with the old token will result in error; example: <configResolveDn dn="sys/chassis-1/blade-1" cookie="1607722287/7a0aa294-1d6a-44b6-abc3-15c65b157183" response="yes" errorCode="552" invocationResult="service-unavailable" errorDescr="Authorization required"> </configResolveDn>
            tokenResponse = callUcsApi(host, refreshBody)
          end
        end
      else
        log.info "No existing token; logging into UCS"
        loginBody = "<aaaLogin inName=\"#{fullUsername}\" inPassword=\"#{password}\"></aaaLogin>"
        tokenResponse = callUcsApi(host, loginBody)
      end

      token = tokenResponse[/outCookie="([\w\/-]+)"/,1]

      File.open(@@tokenFile, "w") do |f|
        f.write(token)
      end
      return token
    end

    def get_full_username(domain, username)
      if domain.nil?
        fullUsername = username
      else
        fullUsername = "#{domain}\\#{username}"
      end
      fullUsername
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
