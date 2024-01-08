# Update

This is a fork of the original parser by josepfontana: https://github.com/josepfontana/parse-ns

- [Jan 8 2024] Adds Python 3 support
- [Jan 8 2024] Adds support for "add service" (in addition to existing "add serviceGroup")
- [Jan 8 2024] Captures [other parameters], such as "-gslb NONE -maxClient 0 -maxReq 0..." in services and puts them (without parsing) into Other Params column
- [Jan 8 2024] Adds basic support for unparseable lines


# parse-ns
Parse Citrix Netscaler configuration and output 2 csv files:
  - one for load balancing with the backend IP(s) and their correspondence with frontend IP (YYYY-MM-DD_HH.MM_LB.csv)
  - another for global server load balance with the domains and their corresponding IP(s) (YYYY-MM-DD_HH.MM_GSLB.csv)


Usage:

  parse-ns.py conf1.txt conf2.txt ...

Output:
  date_GSLB.csv - File with GSLB configuration
  date_LB.csv - File with LB configuration
  date_UNPARSEABLE.csv - Any lines that were not identified

# Understanding Netscaler config

The key to understanding Netscaler config is to realize most of the
configuration is done the other way around than open source load balancers - it
starts with creating backend (real) servers that are tied together and any
frontend listening is done as a final step.

For example:

- When Netscaler does "add server" this means creating a backend server
- When Netscaler does "bind serviceGroup" or "add service" it's creating a collection of backend servers into a single backend
- Finally, when a vserver is added, that's creating a bind for a frontend to listen to on a specific IP


## HAProxy relationship

- "add server" -> server name in backend
- "add service" or "bind serviceGroup" -> backend name
- "add lb vserver" -> frontend name
