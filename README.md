# Filter plugin for appending various field in the record from UCS syslog for [Fluentd](http://fluentd.org)

## Requirements

| fluent-plugin-process-ucs-syslog | fluentd | ruby |
|----------------------------------|---------|------|
| >= 1.0.0 | >= v0.14.0 | >= 2.1   |
|  < 1.0.0 | >= v0.12.0 | >= 1.9   |

## Configuration

    <filter **>
        @type add_machine_id
        ucsHostNameKey SyslogSource
        coloregion SJC2
        domain mydomain
        username myusername
        passwordFile /etc/password/ucsPassword
    </filter>

Will add new hash to record call "machineId" using the detected chassis and blade.

Will check syslog message for the following regex pattern:
    
    sys\/chassis-\d\/blade-\d

If not found, the message will get passed on unchanged.
If found, will log in to UCS using the 'SyslogSource' record from the source and using mydomain\myusername and password in password file in /etc/password/ucsPassword. The login token will be cached in /tmp/token. It will then query UCS for the service profile associated with the chassis and blade id. Along with the provided COLO Region, the machine ID will be generated.

Machine ID format:

    Cisco_UCS:<coloregion>:<serviceProfile>

Will also add record called "stage" using the detected FSM tag.

    [FSM:BEGIN] => begin
    [FSM:END] => end
    [FSM:STAGE:REMOTE-ERROR] => nil

Will also add record called "event: using detected known events.

    Power-on => Boot
    Soft shutdown => Soft Shutdown
    Hard shutdown => Hard Shutdown
    Power-cycle => Restart