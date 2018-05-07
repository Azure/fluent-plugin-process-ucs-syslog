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
        coloregion SJC2
        domain testDomain
        username testUsername
        passwordFile /etc/password/ucsPassword
      ]

    BAD_LOGIN_CONFIG = %[
        @type process_ucs_syslog
        ucsHostNameKey SyslogSource
        coloregion SJC2
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
                if body == "<aaaLogin inName=\"testDomain\\testUsername\" inPassword=\"testPassword\"></aaaLogin>" && host == "1.1.1.1"
                    return '<aaaLogin cookie="" response="yes" outCookie="1111111111/12345678-abcd-abcd-abcd-123456789000"> </aaaLogin>'
                elsif body == "<configResolveDn cookie=\"1111111111/12345678-abcd-abcd-abcd-123456789000\" dn=\"sys/chassis-4/blade-7\"></configResolveDn>" && host == "1.1.1.1"
                    return '<lsServer assignedToDn="org-root/org-T100/ls-testServiceProfile"/>'
                elsif body == "<configResolveDn cookie=\"1111111111/12345678-abcd-abcd-abcd-123456789000\" dn=\"sys/chassis-4/blade-5\"></configResolveDn>" && host == "1.1.1.1"
                    return '<lsServer assignedToDn=""/>'
                elsif body == "<aaaLogin inName=\"testDomain\\badUsername\" inPassword=\"testPassword\"></aaaLogin>" && host == "1.1.1.1"
                    return '<aaaLogin cookie="" response="yes" errorCode="551" invocationResult="unidentified-fail" errorDescr="Authentication failed"> </aaaLogin>'
                elsif body == "<configResolveDn cookie=\"\" dn=\"sys/chassis-4/blade-9\"></configResolveDn>" && host == "1.1.1.1"
                    return '<configResolveDn errorCode="552" errorDescr="Authorization required"> </configResolveDn>'
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

    def test_filter
        records = [
            { 
                "message" => ": 2018 Feb  9 21:07:41 GMT: %UCSM-6-EVENT: [] [FSM:BEGIN]: Soft shutdown of server sys/chassis-4/blade-7",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        assert_equal records[0]['message'], filtered_records[0]['message']
        assert_equal 'Cisco_UCS:SJC2:org-root/org-T100/ls-testServiceProfile', filtered_records[0]['machineId']
        assert_equal 'Soft Shutdown', filtered_records[0]['event']
        assert_equal 'begin', filtered_records[0]['stage']
    end

    def test_filter_no_stage_and_event
        records = [
            { 
                "message" => "2018 Feb  9 21:07:45 GMT: %UCSM-3-LINK_DOWN: [link-down][sys/chassis-4/blade-7/fabric-A/path-3/vc-1518]",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        filtered_records = filter(records)
        assert_equal records[0]['message'], filtered_records[0]['message']
        assert_equal 'Cisco_UCS:SJC2:org-root/org-T100/ls-testServiceProfile', filtered_records[0]['machineId']
        assert_equal "", filtered_records[0]['event']
        assert_equal "", filtered_records[0]['stage']
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

    def test_filter_bad_login
        records = [
            { 
                "message" => "2018 Feb  9 21:07:45 GMT: %UCSM-3-LINK_DOWN: [link-down][sys/chassis-4/blade-9/fabric-A/path-3/vc-1518]",
                "SyslogSource" => "1.1.1.1"
            }
        ]
        if File.exist?(@@tokenFile)
            File.delete(@@tokenFile)
        end
        filtered_records = filter(records, BAD_LOGIN_CONFIG)
        assert_equal "", filtered_records[0]['machineId']
        assert_equal "Unable to login to UCS to get service profile", filtered_records[0]['error']
    end
end