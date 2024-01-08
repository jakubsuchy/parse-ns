# Update

This is a fork of the original parser by josepfontana: https://github.com/josepfontana/parse-ns

- [Jan 8 2024] Adds Python 3 support
- [Jan 8 2024] Adds support for "add service" (in addition to existing "add serviceGroup")


# parse-ns
Parse Citrix Netscaler configuration and output 2 csv files:
  - one for load balancing with the backend IP(s) and their correspondence with frontend IP (YYYY-MM-DD_HH.MM_LB.csv)
  - another for global server load balance with the domains and their corresponding IP(s) (YYYY-MM-DD_HH.MM_GSLB.csv)


Usage:

  parse-ns.py conf1.txt conf2.txt ...
