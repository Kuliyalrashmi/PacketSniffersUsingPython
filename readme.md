<img src = "https://github.com/user-attachments/assets/0046b0cd-3c16-4dd2-9e69-aea377692be1" height =400px  >

# Python Packet Sniffer

A powerful and efficient packet sniffer built using Python and Scapy, capable of capturing and analyzing network traffic in real-time. This tool is designed for network analysis, troubleshooting, and educational purposes, providing insights into various network protocols and metrics.

---

## 🚀 Features

- **Real-Time Packet Capture**: Sniffs packets directly from the network interface.
- **Protocol Support**: Supports multiple protocols, including IP, TCP, UDP, HTTP, and more.
- **User-Friendly Output**: Displays protocol, source, destination, and packet length.
- **Extensibility**: Can be easily extended to support additional protocols or custom analysis.

---

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- Python 3.7+
- `scapy` library  
  Install using pip:  
  ```bash
  pip install scapy
  ```

---

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/YourUsername/Packet-Sniffer.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Packet-Sniffer
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚦 Usage

1. Run the packet sniffer with administrative privileges:
   ```bash
   sudo python packet_sniffer.py
   ```
2. Follow the prompts or edit the configuration to specify network interfaces or filter options.

---

## ⚙️ Configuration

You can modify the following options in the code:

- **Interface**: Change the network interface to capture packets from.
- **Filters**: Add custom filters for specific packet types (e.g., HTTP traffic).
- **Output Format**: Customize how packet details are displayed.

---

## 📂 File Structure

```
Packet-Sniffer/
├── packet_sniffer.py      # Main Python script
├── requirements.txt       # List of dependencies
├── README.md              # Project documentation
└── LICENSE                # License file
```

---

## 🛡️ License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

## 🤝 Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve the functionality or add new features.

---

## 🙋‍♀️ Support

If you encounter any issues or have questions, please open an issue in the repository or reach out to me.

---

## 📜 Disclaimer

This tool is intended for educational and lawful purposes only. Unauthorized use of this tool for malicious purposes is strictly prohibited.
