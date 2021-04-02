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
  
  ## Connection limit variables
  # set max connections per client IP
  set static::maxConnections 3
  
  ## RPS limit variables
  # static var for maximum queries per second
  set static::maxquery 30
  # static var for holdtime
  set static::holdtime 5
  # static var to toggle throttling
  set static::throttle 1
}

when CLIENT_ACCEPTED {
  set mysession [IP::remote_addr]:[TCP::remote_port]
#   set mysession [IP::remote_addr]
  set virtual [virtual]([clientside {IP::local_addr}]:[ clientside {TCP::local_port}])
  set start_time($mysession) [clock clicks -milliseconds]
  set maxRpsCount 0
  
  set tbl "connlimit:[IP::client_addr]"
  set connkey "[TCP::client_port]"
  table set -subtable $tbl $connkey "ignored" 180
  if { [table keys -subtable $tbl -count] > $static::maxConnections } {
    table delete -subtable $tbl $connkey
    event disable all
    reject
    call logger "CLIENT-CONNECTION-LIMIT-REACHED" "Exceeded $static::maxConnections connections rejecting-connection" $mysession $virtual $start_time($mysession)
  } else {
    set timer [after 60000 -periodic { table lookup -subtable $tbl $connkey }]
  }
  TCP::collect
}

when CLIENT_DATA {
  set srcip [IP::remote_addr]
  set tcplen [TCP::payload length]

  # set reqkey to the sourceIP and current time
  set curtime [clock second]
  set reqkey "count:$mysession:$curtime"
  # Keep a count of the entries in the table for this IP in the current second (ie 12<!--:21:01 - 12:21:02)-->
  set count [table incr $reqkey]

  # Time significance is 1s, so expire any entries after 2s (fudge factor) to conserve memory
  table lifetime $reqkey 2

  #  If there is a match, drop the request and exit the event
  if { ([table lookup -subtable "holdlist" $mysession] != "") && $static::throttle } {
    call logger "CLIENT-IS-ON-HOLDLIST" "Waiting for $static::holdtime seconds." $mysession $virtual $start_time($mysession)
    after [expr {($static::holdtime) * 1000 }]
    table delete -subtable "holdlist" $mysession
    call logger "CLIENT-SESSION-RESUMING" "Resuming session." $mysession $virtual $start_time($mysession)
  }

  if { ( $count > $static::maxquery ) && $static::throttle } {  
     # Add IP to the holdlist and set the lifetime to the holdtime variable 
     # so entry will automatically expire when desired.  The lifetime is used
     # instead of the timeout because the first thing the iRule does is lookup
     # the IP in the holdlist table, which would keep the timeout from expiring
     # the holdlist entry.
     call logger "CLIENT-EXCEEDED-THRESHOLD" "$count requests per second" $mysession $virtual $start_time($mysession)
     table add -subtable "holdlist" $mysession "blocked" indef $static::holdtime
     call logger "CLIENT-PLACED-ON-HOLDLIST" "Putting on holdlist for $static::holdtime seconds." $mysession $virtual $start_time($mysession)
     # Reset count to avoid subsequent warnings and entries for the same client connection.
     table delete $reqkey
  }
  
  if { $count > $maxRpsCount } {
    set maxRpsCount $count
  }
  #Release collected data
  TCP::release
  # Collect new data - CLIENT_DATA will be called again
  TCP::collect  
}

when SERVER_CONNECTED {
  call logger "LB-DECISION-MADE" "serverside-f5-ip=[IP::local_addr]:[TCP::local_port], pool-member=[LB::server addr]:[LB::server port]" $mysession $virtual $start_time($mysession)
  if { $static::log_requests } {
  }
}

when CLIENT_CLOSED {
  after cancel $timer
  table delete -subtable $tbl $connkey
#   call logger "DELETING-TABLE-ENTRY" "table=$tbl, connkey=$connkey" $mysession $virtual $start_time($mysession)
  call logger "CLIENT-SESSION-CLOSED" "Max-RPS=$maxRpsCount" $mysession $virtual $start_time($mysession)
}