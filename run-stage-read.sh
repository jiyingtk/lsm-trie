sudo src/staged_read -v 64 -d tmp -c cm_conf_ssd.txt -a 32 -n 800000 2>&1 | tee -a log-staged_read-`date +%Y-%m-%d-%H_%M_%S`.txt
