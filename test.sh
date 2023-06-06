#!/bin/sh
while true; do

    start=$SECONDS

    # start_time=$(date +%s.%N)
    ### Currently capturing 100 packets and then convering it to csv file named dump_ISCX.csv at project/TCPDUMP_and_CICFlowMeter/csv
    sh capture_interface_pcap.sh wlp170s0 pcap vijay


    echo "THIS IS HAPPENING "

    capture_duration=$((SECONDS - start))
    echo The capture process took $capture_duration seconds to capture and convert

    ### Call model.py to check for intrusions in the captured traffic
    # python model_final.py
    model_start=$SECONDS
    python model.py
    model_duration=$((SECONDS - model_start))
    echo ML model took $model_duration seconds to complete analysis

    echo "Flagging the IP addresses"

    while read line; do
    
    sudo ufw deny from $line to any;
    sudo ufw status

    done < ips.txt

    # end_time=$(date +%s.%N)
    duration=$((SECONDS - start))
    echo $duration
    
    echo Previous cycle execution Time was $duration seconds

    # echo $run_time >> $outputfile

    #sudo ufw deny from xxx.xxx.xxx.xxx to any

    #sudo ufw status

    
done 