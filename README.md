# WHS-network-PCAP-Programming

libpcap 설치 및 코드 컴파일: 
sudo apt update
sudo apt install -y libpcap-dev gcc


코드 컴파일(sniff.c와 myheader.h가 같은 폴더에 있는 상태)
gcc -o sniff sniff.c -lpcap

코드 실행
sudo ./sniff

