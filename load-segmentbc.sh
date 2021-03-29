sudo src/mixed_test-segmentbc -v 64 -d tmp -c cm_conf_ssd.txt -t 72000 -s 966367641600 2>&1 | tee -a log-load-sbc-`date +%Y-%m-%d-%H_%M_%S`.txt
