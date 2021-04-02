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
  set static::rate "30Mbps"
  set static::bwcPolicy "jw-bwc"
  set static::measureRate "200"
  set static::syslog_hsl_rule_syslog_pool "my_syslog_pool"
  set static::syslog_hsl_rule_proto "UDP"
  set static::syslog_hsl_rule_pri "<134>"
  set static::syslog_hsl_rule_this_host [info hostname]
  set static::log_to_local 1
}

when CLIENT_ACCEPTED {
  set mysession [IP::remote_addr]:[TCP::remote_port]
#   set mysession [IP::remote_addr]
  set virtual [virtual]([clientside {IP::local_addr}]:[ clientside {TCP::local_port}])
  set start_time($mysession) [clock clicks -milliseconds]
  
  BWC::policy attach $static::bwcPolicy $mysession
  BWC::rate $mysession $static::rate
  BWC::measure identifier $mysession session
  BWC::measure start session
}
when SERVER_CONNECTED {
  call logger "LB-DECISION-MADE" "serverside-f5-ip=[IP::local_addr]:[TCP::local_port], pool-member=[LB::server addr]:[LB::server port]" $mysession $virtual $start_time($mysession)
  TCP::collect
  set bwcMCount 0
}
when SERVER_DATA {
  if {$bwcMCount >= $static::measureRate } {
    call logger "MOVING-AVERAGE" "$rate bytes/sec : $bytes total" $mysession $virtual $start_time($mysession)
    set bwcMCount 0
  }
  incr bwcMCount
  set rate [BWC::measure get rate session]
  set bytes [BWC::measure get bytes session]
  TCP::release
  TCP::collect
}

when SERVER_CLOSED {
  call logger "SESSION-CLOSED" "$rate bytes/sec : $bytes total" $mysession $virtual $start_time($mysession)
}