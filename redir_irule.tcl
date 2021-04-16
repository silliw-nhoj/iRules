# Data-group with host as key and string as value for redirect location
ltm data-group internal redirect-dg {
    records {
        app1.example.com {
            data example.com/app1
        }
        app2.example.com {
            data example.com/app2
        }
        app3.example.com {
            data example.com/app3
        }
        zoom.sfusd.edu {
            data sfusd.zoom.us/signin
        }
    }
    type string
}

# iRule that references the above data-group
ltm rule redir-rule {
  when HTTP_REQUEST {
    # get matching values from data-group based on host
    set redir [class match -value -- [string  tolower [HTTP::host]] contains redirect-dg]
    if { $redir ne "" } {
      HTTP::redirect "https://$redir"
    }
  }
}