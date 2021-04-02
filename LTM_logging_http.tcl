# Requirements:
#   1. Syslog LTM pool (update variable static::syslog_hsl_rule_syslog_pool)
#   2. HTTP profile on VS

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

# Static Variables
when RULE_INIT {
  # set static var for syslog pool
  set static::syslog_hsl_rule_syslog_pool "my_syslog_pool"
  # HSL connection vars (UPDATE as needed!)
  set static::syslog_hsl_rule_proto "UDP"
  set static::syslog_hsl_rule_pri "<134>"
  # get hostname from local device
  set static::syslog_hsl_rule_this_host [info hostname]
  # static var to toggle logging of tcp info
  set static::syslog_hsl_rule_log_tcp_info 1
  # static var to toggle logging of http info
  set static::syslog_hsl_rule_log_http_info 1
  # static var to toggle local logging
  set static::log_to_local 1
}

# connection established
when CLIENT_ACCEPTED {
  set mysession [IP::remote_addr]:[TCP::remote_port]
# set mysession [IP::remote_addr]
  set virtual [virtual]([clientside {IP::local_addr}]:[ clientside {TCP::local_port}])
  set start_time($mysession) [clock clicks -milliseconds]
  if { $static::syslog_hsl_rule_log_tcp_info } {
    call logger "CLIENT-TCP-CONN-ESTABLISHED" "--" $mysession $virtual $start_time($mysession)
  }
}


# LB decision made and pool member selected
when SERVER_CONNECTED {
  if { $static::syslog_hsl_rule_log_tcp_info } {
    call logger "LB-DECISION-MADE" "serverside-f5-ip=[IP::local_addr]:[TCP::local_port], pool-member=[LB::server addr]:[LB::server port]" $mysession $virtual $start_time($mysession)
  }
}

# HTTP request received from client
when HTTP_REQUEST {
  if { $static::syslog_hsl_rule_log_http_info } {
    call logger "HTTP-REQUEST-RECEIVED" "request-URI=[HTTP::uri], user-agent=[HTTP::header user-agent]" $mysession $virtual $start_time($mysession)
  }
}

# HTTP response received from server
when HTTP_RESPONSE {
  if { $static::syslog_hsl_rule_log_http_info } {
    call logger "HTTP-RESPONSE-RECEIVED" "status-code=[HTTP::status]" $mysession $virtual $start_time($mysession)
  }
}

# Client TCP connection closed
when CLIENT_CLOSED {
  if { $static::syslog_hsl_rule_log_tcp_info } {
    call logger "CLIENT-CONNECTION-CLOSED" "--" $mysession $virtual $start_time($mysession)
  }
}