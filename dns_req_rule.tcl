ltm rule /Common/dns_connection_rule {
# Common Logging Procedure
proc logger { evt msg mysession virtual startTime } {
  # set timestamp and format with milliseconds
  set timestamp [format "%s.%03d GMT" [clock format [expr {[clock clicks -milliseconds] / 1000}] -format "%d %h %Y %T" -gmt 1] [expr {[clock clicks -milliseconds] % 1000}]]
  set time_now($mysession) [clock clicks -milliseconds]
  set elapsed_time [format "elapsed-time=%03d\ms" [expr { $time_now($mysession) - $startTime }]]
  # default message to show client-IP:client-port and vs-name(vs-IP:vs-port)
  set defMsg "client=$mysession, virtual-server=$virtual"
  # if log_to_local is set log to local0
  if { $static::log_to_local } { log local0. "$timestamp, $evt, $defMsg, $msg, $elapsed_time" }
  # set HSL handle and send 
  set handle [HSL::open -proto $static::syslog_hsl_rule_proto -pool $static::syslog_hsl_rule_syslog_pool]
  HSL::send $handle "$static::syslog_hsl_rule_pri, host=$static::syslog_hsl_rule_this_host, $timestamp, $evt, $defMsg, $msg, $elapsed_time\n"
}

when RULE_INIT {
  ## logging variables
  # set static var for syslog pool
  set static::syslog_hsl_rule_syslog_pool "my_syslog_pool"
  # HSL connection vars (UPDATE as needed!)
  set static::syslog_hsl_rule_proto "UDP"
  set static::syslog_hsl_rule_pri "<134>"
  # get hostname from local device
  set static::syslog_hsl_rule_this_host [info hostname]
  # static var to toggle local logging
  set static::log_to_local 1

  
  ## RPS limit variables
  # static var for maximum queries per second
  set static::maxquery 10
  # static var for holdtime
  set static::holdtime 1
  # static var to toggle throttling
  set static::throttle 1
}

when CLIENT_ACCEPTED {
  set mysession [IP::remote_addr]
#   set mysession [IP::remote_addr]
  set virtual [virtual]([clientside {IP::local_addr}]:[ clientside {UDP::local_port}])
  set start_time($mysession) [clock clicks -milliseconds]
}

when DNS_REQUEST {
  set type [DNS::question type]
  call logger "DNS-REQUEST" "TYPE=$type CLI-PORT=[UDP::client_port]" $mysession $virtual $start_time($mysession)
  
  # set reqkey to the sourceIP and current time
  set curtime [clock second]
  set reqkey "count:$mysession:$curtime"
  # Keep a count of the entries in the table for this IP in the current second (ie 12<!--:21:01 - 12:21:02)-->
  set count [table incr $reqkey]
  # Time significance is 1s, so expire any entries after 2s (fudge factor) to conserve memory
  table lifetime $reqkey 2

  if { ( $count > $static::maxquery ) && $static::throttle } {  
    call logger "CLIENT-EXCEEDED-THRESHOLD" "$count requests per second" $mysession $virtual $start_time($mysession)
    set count [table incr $reqkey -1]
    event disable all
    reject
  } 
}
}