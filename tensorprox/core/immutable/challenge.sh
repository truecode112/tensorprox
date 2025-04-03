#!/bin/bash

# Ensure required tools are installed
if ! command -v jq &> /dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y jq -qq
fi

if ! command -v tcpdump &> /dev/null; then
    sudo apt-get update > /dev/null 2>&1
    sudo apt-get install -y tcpdump > /dev/null 2>&1
fi

machine_name="$1"
challenge_duration="$2"
label_hashes="$3"
playlist_json=$(echo "$4" | jq '.' 2>/dev/null)
king_ip="$5"
traffic_gen_path="$6"

# Build grep patterns for counting occurrences of each label
benign_pattern=$(echo "$label_hashes" | jq -r '.BENIGN | join("|")')
udp_flood_pattern=$(echo "$label_hashes" | jq -r '.UDP_FLOOD | join("|")')
tcp_syn_flood_pattern=$(echo "$label_hashes" | jq -r '.TCP_SYN_FLOOD | join("|")')

# Default values for counts
benign_count=0
udp_flood_count=0
tcp_syn_flood_count=0

# Default RTT value
rtt_avg=10000000

# Define the traffic filtering based on machine_name
if [ "$machine_name" == "king" ]; then
    filter_traffic="(tcp or udp) and inbound and not (tcp[tcpflags] & (tcp-syn|tcp-ack) != 0) and not icmp and not src host $king_ip"
else
    filter_traffic="(tcp or udp) and outbound"
fi

# Traffic generation for attacker and benign
if [[ "$machine_name" == "attacker" || "$machine_name" == "benign" ]]; then

    # Install Python3 and pip if not installed
    if ! command -v python3 &>/dev/null; then
        sudo apt-get update && sudo apt-get install -y python3 python3-pip
    fi

    # Install necessary Python packages
    for package in faker scapy pycryptodome; do
        if ! python3 -c "import $package" &>/dev/null; then
            sudo pip3 install $package > /dev/null 2>&1
        fi
    done

    # Dump playlist into temporary json file
    echo "$playlist_json" > /tmp/playlist.json

    # Start traffic generator with the playlist
    nohup python3 $traffic_gen_path --playlist /tmp/playlist.json --receiver-ips $king_ip --interface ipip-$machine_name > /tmp/traffic_generator.log 2>&1 &

    # Start continuous ping in background
    INTERFACE_IP=$(ip -4 addr show ipip-"$machine_name" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    nohup ping -I "$INTERFACE_IP" -c "$challenge_duration" "$king_ip" > /tmp/rtt.txt 2>&1 &

fi

sudo timeout "$challenge_duration" tcpdump -A -l -nn -i gre-moat "$filter_traffic" 2>/dev/null | \
    awk 'BEGIN { benign=0; udp_flood=0; tcp_syn_flood=0 } { 
        payload = $0;
        if (payload ~ /'"$benign_pattern"'/) benign++;
        if (payload ~ /'"$udp_flood_pattern"'/) udp_flood++;
        if (payload ~ /'"$tcp_syn_flood_pattern"'/) tcp_syn_flood++;
    } 
    END { print "BENIGN:"benign", UDP_FLOOD:"udp_flood", TCP_SYN_FLOOD:"tcp_syn_flood }' > /tmp/counts.txt &

wait  # Ensure tcpdump finishes before reading counts

# Read counts from /tmp/counts.txt
counts=$(cat /tmp/counts.txt)

# Measure RTT if the machine is attacker or benign
if [[ "$machine_name" == "attacker" || "$machine_name" == "benign" ]]; then

    # Extract average RTT from the ping output (assuming the ping command ran successfully)
    extracted_rtt=$(grep -oP 'rtt min/avg/max/mdev = \d+\.\d+/(\d+\.\d+)' /tmp/rtt.txt | awk -F'/' '{print $5}')

    # Update rtt_avg only if extracted_rtt is not empty
    if [[ ! -z "$extracted_rtt" ]]; then
        rtt_avg=$extracted_rtt
    fi

    # Output the counts along with the average RTT
    echo "$counts, AVG_RTT:$rtt_avg"
else
    # Output just the counts if the machine is neither attacker nor benign
    echo "$counts"
fi

# Delete temporary files
rm -f /tmp/capture.pcap
rm -f /tmp/playlist.json
rm -f /tmp/rtt.txt
rm -f /tmp/counts.txt