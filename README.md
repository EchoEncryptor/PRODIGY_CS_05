# 📡 Simple Packet Sniffer Tool

## 🔍 Description

This is a lightweight **packet sniffing tool** built with **Python** and **Scapy** that captures and displays real-time network traffic. It shows critical details like:

- Source and destination IP addresses  
- Protocol type (TCP, UDP, ICMP, etc.)  
- Port numbers (where applicable)  
- Payload data preview (first 50 bytes)

> ⚠️ **Root privileges are required** to capture live network packets.

---

## ✨ Features

- 🕵️‍♂️ Captures live packets on any network interface
- 🧠 Automatically detects IP-based protocols: **TCP**, **UDP**, **ICMP**
- 🔍 Displays:
  - IP address info
  - Port numbers
  - ICMP type
  - First 50 bytes of raw payload
- 🎯 Optional BPF filtering (e.g., `tcp port 80`)
- 🔄 Works indefinitely or for a specific number of packets
- ✅ Minimal, human-readable output

---

## 🧰 Requirements

- Python 3.x
- `scapy` library

Install Scapy:

```bash
pip install scapy
```

---

## 🚀 Usage

```bash
sudo python3 packet_sniffer.py [-i INTERFACE] [-c COUNT] [-f FILTER]
```

### 🔧 Arguments

| Argument | Description |
|----------|-------------|
| `-i`, `--interface` | Network interface to sniff on (e.g., `eth0`, `wlan0`) |
| `-c`, `--count`     | Number of packets to capture (`0` for infinite) |
| `-f`, `--filter`    | Optional BPF (Berkeley Packet Filter) string (e.g., `"tcp port 443"`) |

### 📌 Example

```bash
sudo python3 packet_sniffer.py -i eth0 -c 10 -f "tcp port 80"
```

Captures 10 TCP packets on port 80 from interface `eth0`.

---

## 📦 Sample Output

```
[TCP] 192.168.1.10 -> 172.217.3.110
    Ports: 51234 -> 80
    Payload: b'GET / HTTP/1.1\r\nHost: examp...' ...

[ICMP] 192.168.1.10 -> 8.8.8.8
    ICMP Type: 8
```

---

## 📁 File Structure

```
packet_sniffer.py    # Main script
```

---

## 🛡️ Legal & Ethical Use

This tool is intended for:

- **Educational purposes**
- **Network diagnostics**
- **Authorized environments only**

> ❗ **Do NOT use this tool on networks you do not own or without explicit permission. Unauthorized use may violate privacy laws and result in criminal penalties.**

---

## 📃 License

This project is open-source under the [MIT License](LICENSE).

---

## 📌 Future Enhancements (Optional Ideas)

- Write captured data to `.pcap` file
- Add GUI with live packet stats
- Protocol breakdown (DNS, HTTP, TLS)
- Cross-platform support via `pyshark` or `pcapy`

