# NetworkTool

## What is NetworkTool?
This script is a flexible network scanning framework that allows users to perform various types of network scans including **Recon**, **Generic**, **SegmentationCheck**, and **Nmap** scans. The script leverages the Nmap tool and provides advanced reporting functionalities, allowing users to save scan results in text, markdown, and JSON formats.

## How to Install
To install the script and its dependencies, follow the steps below:

### Prerequisites
1. **Python**: Ensure you have Python 3.x installed on your system.
2. **Nmap**: Install Nmap, which is used by the script.

### Installation Steps
1. Clone the repository or download the script file to your local machine.
2. Install Nmap on your system using the following:
    ```bash
    sudo apt-get install nmap
    ```
3. Navigate to the script directory and install the required Python libraries:
    ```bash
    pip install -r requirements.txt
    ```

`requirements.txt`:

```text
libnmap
colorama
netifaces
```

## Scans

### Recon Scan
This scan is designed to work in a cascade fashion:
1. **Ping Scan**: Detects live hosts.
2. **Ping Scan + SYN Scan**: Runs SYN scan on live hosts.
3. **Ping Scan + SYN Scan + Version Detection**: Detects service versions.
4. **Ping Scan + SYN Scan + Aggressive Scan**: Performs an aggressive scan with OS detection, version detection, and more.

#### Parameters for Recon Scan:
- `--target`: Specify the target IP or domain (optional).
- `--output`: Specify the output file path (e.g., `results.txt`, `results.md`, `results.json`).
- `--mode`: Choose between `silent` and `normal` modes.

#### Example:
```bash
python3 NetworkTool.py Recon --target 192.168.1.1 --output results.json --mode normal
```

### Generic Scan
This scan allows users to select from a set of predefined Nmap scan options like TCP connect scan, SYN scan, UDP scan, and more.

#### Parameters for Generic Scan:
- `--target`: Specify the target IP or domain (required).
- `--ports`: Specify the ports to scan (optional).
- `--ping-off`: Disable ping (host discovery) during the scan.
- `--output`: Specify the output file path.
- `--mode`: Select between `silent` and `normal` scan modes.

#### Example:
```bash
python3 NetworkTool.py Generic --target 192.168.1.0/24 --ports 80,443 --output results.md --mode silent
```

### SegmentationCheck Scan
This scan is focused on testing the security and segmentation of networks using various techniques like TCP ACK Scan, Fragmentation Scan, and more.

#### Parameters for SegmentationCheck Scan:
- `--target`: Specify the target IP or domain (required).
- `--output`: Specify the output file path.
- `--mode`: Select between `silent` and `normal` scan modes.

#### Example:
```bash
python3 NetworkTool.py SegmentationCheck --target 192.168.1.0/24 --output segmentation.txt --mode normal
```

### Nmap Custom Scan
This option allows users to directly provide Nmap flags and options as they would with a normal Nmap command. The script will accept the flags and arguments in the same format as when using the Nmap tool.

#### Important Note:
When using the `nmap` scan, the `--output` option (for saving reports) should be placed **between** the `nmap` command and the target IP address.

#### Example:
```bash
python3 NetworkTool.py nmap --output results.json -sT -Pn 192.168.1.1
```

## Reporting Functionalities
The script supports generating reports in three formats:
- **Text (`.txt`)**
- **Markdown (`.md`)**
- **JSON (`.json`)**

To specify the report format, use the `--output` option. The script will store the scan results in the specified file, handling multiple IP addresses and storing their results efficiently.

### Example with Reporting:
```bash
python3 NetworkTool.py Recon --target 192.168.1.0/24 --output report.json
```

This command will run a recon scan on the 192.168.1.0/24 network and save the results to `report.json`.
