require 'fluent/test'
require 'fluent/test/driver/filter'
require 'fluent/plugin/filter_process_ucs_syslog'

class ProcessUcsSyslog < Test::Unit::TestCase
    def setup
        Fluent::Test.setup
    end

    @@tokenFile = "/tmp/token"

    CONFIG = %[
        @type process_ucs_syslog
        ucsHostNameKey SyslogSource
        coloregion FakeColo
        domain testDomain
        username testUsername
        passwordFile /etc/password/ucsPassword
      ]

    BAD_LOGIN_CONFIG = %[
        @type process_ucs_syslog
        ucsHostNameKey SyslogSource
        coloregion FakeColo
        domain testDomain
        username badUsername
        passwordFile /etc/password/ucsPassword
      ]

    def create_driver(conf)
        Fluent::Test::Driver::Filter.new(Fluent::Plugin::ProcessUcsSyslog) do
            # for testing
            def getPassword()
                return 'testPassword'
            end

            def callUcsApi(host, body)
                if body.delete(' ') == "<aaaLogin inName=\"testDomain\\testUsername\" inPassword=\"testPassword\"></aaaLogin>".delete(' ') && host == "1.1.1.1"
                    return '<aaaLogin cookie="" response="yes" outCookie="1111111111/12345678-abcd-abcd-abcd-123456789000"> </aaaLogin>'
                elsif body.delete(' ') == "<configResolveDn cookie=\"1111111111/12345678-abcd-abcd-abcd-123456789000\" dn=\"sys/chassis-4/blade-7\"></configResolveDn>".delete(' ') && (host == "1.1.1.1" || host == "1.1.1.2")
                    return '<lsServer assignedToDn="org-root/org-T100/ls-testServiceProfile"/>'
                elsif body.delete(' ') == "<configResolveDn cookie=\"1111111111/12345678-abcd-abcd-abcd-123456789000\" dn=\"sys/chassis-14/blade-7\"></configResolveDn>".delete(' ') && host == "1.1.1.1"
                    return '<lsServer assignedToDn="org-root/org-T100/ls-testServiceProfile2"/>'
                elsif body.delete(' ') == "<configResolveDn cookie=\"1111111111/12345678-abcd-abcd-abcd-123456789000\" dn=\"sys/chassis-4/blade-17\"></configResolveDn>".delete(' ') && host == "1.1.1.1"
                    return '<lsServer assignedToDn="org-root/org-T100/ls-testServiceProfile3"/>'
                elsif body.delete(' ') == "<configResolveDn cookie=\"1111111111/12345678-abcd-abcd-abcd-123456789000\" dn=\"sys/chassis-4/blade-5\"></configResolveDn>".delete(' ') && host == "1.1.1.1"
                    return '<lsServer assignedToDn=""/>'
                elsif body.delete(' ') == "<aaaLogin inName=\"testDomain\\badUsername\" inPassword=\"testPassword\"></aaaLogin>".delete(' ') && host == "1.1.1.1"
                    return '<aaaLogin cookie="" response="yes" errorCode="551" invocationResult="unidentified-fail" errorDescr="Authentication failed"> </aaaLogin>'
                elsif body.delete(' ') == "<configResolveDn cookie=\"\" dn=\"sys/chassis-4/blade-9\"></configResolveDn>".delete(' ') && host == "1.1.1.1"
                    return '<configResolveDn errorCode="552" errorDescr="Authorization required"> </configResolveDn>'
                elsif body.delete(' ') == "<configResolveClass
                        cookie=\"1111111111/12345678-abcd-abcd-abcd-123456789000\"
                        inHierarchical=\"false\"
                        classId=\"faultInst\">
                        <inFilter>
                        <and>
                            <eq class=\"faultInst\"
                                property=\"cause\"
                                value=\"link-down\" />
                            <wcard class=\"faultInst\" 
                                property=\"dn\" 
                                value=\"sys/chassis-4/blade-7\" />
                            <ne class=\"faultInst\"
                                property=\"severity\"
                                value=\"cleared\" />
                        </and>
                        </inFilter>
                    </configResolveClass>".delete(' ') && host == "1.1.1.1"
                    return "<configResolveClass cookie=\"1525812904/746212b9-9f21-4691-a069-43e93926a3fd\" response=\"yes\" classId=\"faultInst\"><outConfigs></outConfigs></configResolveClass>"
                else
                    return ''
                end
            end
        end.configure(conf)
    end

    def filter(records, conf = CONFIG)
        d = create_driver(conf)
        d.run(default_tag: "default.tag") do
            records.each do |record|
                d.feed(record)
            end
        end
        d.filtered_records
    end

    def test_configure
        d = create_driver(CONFIG)
        assert_equal 'testDomain', d.instance.domain
        assert_equal 'testUsername', d.instance.username
    end

    def test_event_filter
        records = [
            { 
                "message" => ": 2018 May  3 00:05:36 IST: %UCSM-6-EVENT: [E4195921][8743116][transition][ucs-HANATDIT][] [FSM:BEGIN]: Soft shutdown of server sys/chassis-4/blade-7(FSM:sam:dme:ComputePhysicalSoftShutdown)",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        assert_equal records[0]['message'], filtered_records[0]['message']
        assert_equal 'Cisco_UCS:FakeColo:org-root/org-T100/ls-testServiceProfile', filtered_records[0]['machineId']
        assert_equal 'soft shutdown', filtered_records[0]['event']
        assert_equal 'begin', filtered_records[0]['stage']
        assert_equal 'event', filtered_records[0]['type']
        assert_equal 'info', filtered_records[0]['severity']
        assert_equal '', filtered_records[0]['mnemonic']
        assert_equal '', filtered_records[0]['device']
        assert_equal '', filtered_records[0]['error']
    end

    def test_event_filter_double_digit_chassis
        records = [
            { 
                "message" => ": 2018 May  3 00:05:36 IST: %UCSM-6-EVENT: [E4195921][8743116][transition][ucs-HANATDIT][] [FSM:BEGIN]: Soft shutdown of server sys/chassis-14/blade-7(FSM:sam:dme:ComputePhysicalSoftShutdown)",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        assert_equal records[0]['message'], filtered_records[0]['message']
        assert_equal 'Cisco_UCS:FakeColo:org-root/org-T100/ls-testServiceProfile2', filtered_records[0]['machineId']
        assert_equal 'soft shutdown', filtered_records[0]['event']
        assert_equal 'begin', filtered_records[0]['stage']
        assert_equal 'event', filtered_records[0]['type']
        assert_equal 'info', filtered_records[0]['severity']
        assert_equal '', filtered_records[0]['mnemonic']
        assert_equal '', filtered_records[0]['device']
        assert_equal '', filtered_records[0]['error']
    end

    def test_event_filter_double_digit_blade
        records = [
            { 
                "message" => ": 2018 May  3 00:05:36 IST: %UCSM-6-EVENT: [E4195921][8743116][transition][ucs-HANATDIT][] [FSM:BEGIN]: Soft shutdown of server sys/chassis-4/blade-17(FSM:sam:dme:ComputePhysicalSoftShutdown)",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        assert_equal records[0]['message'], filtered_records[0]['message']
        assert_equal 'Cisco_UCS:FakeColo:org-root/org-T100/ls-testServiceProfile3', filtered_records[0]['machineId']
        assert_equal 'soft shutdown', filtered_records[0]['event']
        assert_equal 'begin', filtered_records[0]['stage']
        assert_equal 'event', filtered_records[0]['type']
        assert_equal 'info', filtered_records[0]['severity']
        assert_equal '', filtered_records[0]['mnemonic']
        assert_equal '', filtered_records[0]['device']
        assert_equal '', filtered_records[0]['error']
    end

    def test_audit_filter
        records = [
            { 
                "message" => ": 2018 Mar 15 11:35:35 GMT: %UCSM-6-AUDIT: [admin][ucs-HANATDIT][creation][web_29053_A][7673436][org-root/lan-conn-templ-vNIC-Test-A/if-999-native][defaultNet:no, name:999-native][] Ethernet interface created",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        assert_equal records[0]['message'], filtered_records[0]['message']
        assert_equal '', filtered_records[0]['machineId']
        assert_equal '', filtered_records[0]['event']
        assert_equal '', filtered_records[0]['stage']
        assert_equal 'audit', filtered_records[0]['type']
        assert_equal 'info', filtered_records[0]['severity']
        assert_equal '', filtered_records[0]['mnemonic']
        assert_equal '', filtered_records[0]['device']
        assert_equal '', filtered_records[0]['error']
    end

    def test_fault_filter
        records = [
            { 
                "message" => ": 2018 May 11 19:04:47 IST: %UCSM-4-INSUFFICIENTLY_EQUIPPED: [F0305][cleared][insufficiently-equipped][sys/chassis-4/blade-7] Server 4/5 (service profile: ) has insufficient number of DIMMs, CPUs and/or adapters",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        assert_equal records[0]['message'], filtered_records[0]['message']
        assert_equal 'Cisco_UCS:FakeColo:org-root/org-T100/ls-testServiceProfile', filtered_records[0]['machineId']
        assert_equal '', filtered_records[0]['event']
        assert_equal '', filtered_records[0]['stage']
        assert_equal 'fault', filtered_records[0]['type']
        assert_equal 'cleared', filtered_records[0]['severity']
        assert_equal 'insufficiently-equipped', filtered_records[0]['mnemonic']
        assert_equal 'sys/chassis-4/blade-7', filtered_records[0]['device']
        assert_equal '', filtered_records[0]['error']
    end

    def test_filter_no_username
        records = [
            { 
                "message" => "2018 Apr 30 18:11:59 UTC: %AUTHPRIV-5-SYSTEM_MSG: New user added with username ucs-HANATDI\\test-user.ucs - securityd",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        assert_equal "2018 Apr 30 18:11:59 UTC: %AUTHPRIV-5-SYSTEM_MSG: New user added with username ucs-HANATDI - securityd", filtered_records[0]['message']
    end

    def test_filter_keep_service_account_username
        records = [
            { 
                "message" => "2018 Apr 30 18:11:59 UTC: %AUTHPRIV-5-SYSTEM_MSG: New user added with username testDomain\\testUsername - securityd",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        assert_equal "2018 Apr 30 18:11:59 UTC: %AUTHPRIV-5-SYSTEM_MSG: New user added with username testDomain\\testUsername - securityd", filtered_records[0]['message']
    end

    def test_filter_no_service_profile
        records = [
            { 
                "message" => "2018 Feb  9 21:07:45 GMT: %UCSM-3-LINK_DOWN: [link-down][sys/chassis-4/blade-5/fabric-A/path-3/vc-1518]",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        assert_equal "", filtered_records[0]['machineId']
    end

    def test_filter_internal_reboot
        records = [
            { 
                "message" => ": 2018 May  4 23:04:53 IST: %UCSM-3-LINK_DOWN: [F0283][major][link-down][sys/chassis-4/blade-7/fabric-A/path-3/vc-1494] fc VIF 1494 on server 4 / 3 of switch A  down, reason: Gracefully shutdown",
                "SyslogSource" => "1.1.1.1"
            },
            { 
                "message" => ": 2018 May  4 23:05:08 IST: %UCSM-6-EVENT: [E4196386][8763783][transition][internal][] Adapter 4/7/3 restarted",
                "SyslogSource" => "1.1.1.1"
            },
            { 
                "message" => ": 2018 May  4 23:10:31 IST: %UCSM-3-LINK_DOWN: [F0283][cleared][link-down][sys/chassis-4/blade-7/fabric-A/path-3/vc-1494] fc VIF 1494 on server 4 / 3 of switch A  down, reason: waiting for flogi",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        
        assert_equal records[0]['message'], filtered_records[0]['message']
        assert_equal 'Cisco_UCS:FakeColo:org-root/org-T100/ls-testServiceProfile', filtered_records[0]['machineId']
        assert_equal "", filtered_records[0]['event']
        assert_equal "", filtered_records[0]['stage']

        assert_equal records[1]['message'], filtered_records[1]['message']
        assert_equal 'Cisco_UCS:FakeColo:org-root/org-T100/ls-testServiceProfile', filtered_records[1]['machineId']
        assert_equal "internal restart", filtered_records[1]['event']
        assert_equal "begin", filtered_records[1]['stage']

        assert_equal records[2]['message'], filtered_records[2]['message']
        assert_equal 'Cisco_UCS:FakeColo:org-root/org-T100/ls-testServiceProfile', filtered_records[2]['machineId']
        assert_equal "internal restart", filtered_records[2]['event']
        assert_equal "end", filtered_records[2]['stage']
    end

    def test_filter_bad_login
        records = [
            { 
                "message" => ": 2018 Feb  9 21:07:45 GMT: %UCSM-3-LINK_DOWN: [link-down][sys/chassis-4/blade-9/fabric-A/path-3/vc-1518]",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        if File.exist?(@@tokenFile)
            File.delete(@@tokenFile)
        end
        filtered_records = filter(records, BAD_LOGIN_CONFIG)
        assert_equal "", filtered_records[0]['machineId']
        assert_equal "Error getting service profile: Unable to login to UCS", filtered_records[0]['error']
    end
end
