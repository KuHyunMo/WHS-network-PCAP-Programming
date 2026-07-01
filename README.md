# WHS-network-PCAP-Programming

libpcap 설치 및 코드 컴파일:<br>
sudo apt update<br>
sudo apt install -y libpcap-dev gcc<br>
<br>


코드 컴파일(sniff.c와 myheader.h가 같은 폴더에 있는 상태)<br>
gcc -o sniff sniff.c -lpcap<br>
<br>
코드 실행<br>
sudo ./sniff<br>
