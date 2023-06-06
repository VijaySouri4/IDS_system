
<!------------------------------------------------------------------------------------------------->
# Introduction
<!------------------------------------------------------------------------------------------------->

This project is about capturing packets flow through a network interface,
    save each specific-size chunk into a PCAP file,
    automatically convert it to the feature-extracted CSV file by
    CICFlowMeter-4.0.
    and then analyze the csv file with an XGBoost model trained on CIC-IDS2017 dataset. 

For more infomation on CICFlowMeter please follow the link (http://www.unb.ca/cic).

This project is developed and tested on Ubuntu 22. 
This project requries TCPdump, and TCPreplay which can be installed via 
```sudo apt install tcpdump```
```sudo apt install tcpreplay```

Python requirements for this project can be installed via the requirements.txt file 
in this repository.


<!------------------------------------------------------------------------------------------------->
# Usage
<!------------------------------------------------------------------------------------------------->

## To Run the IDS system:

Change the interface of the network adapter in line 8 of the ```test.sh```
i.e change the wlp170s0 from ```sh capture_interface_pcap.sh wlp170s0 pcap vijay```
to a network interface over which you want to run the IDS. 

Use the test.sh shell script to listen over the interface.  


```bash
bash test.sh
```
