# nstree - A simple and visual DNS resolution CLI tool"
![nstree](https://img.shields.io/badge/version-1.0-green) ![Python](https://img.shields.io/badge/python-3.x-blue) ![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![alt text](https://github.com/atenreiro/nstree/blob/main/screenshots/nstree.png)

**nstree** is a powerful DNS Resolution Tool that allows you to perform comprehensive DNS queries for multiple domains. It supports various DNS record types and can visualize the DNS resolution hierarchy using Graphviz diagrams. Whether you're troubleshooting DNS issues, analyzing domain configurations, or simply exploring DNS records, `nstree` provides an efficient and user-friendly solution.

## Features

- **Asynchronous DNS Resolution:** Quickly resolve multiple domains concurrently.
- **Support for Multiple DNS Record Types:** Query A, MX, CNAME, NS, TXT, AAAA, SOA, PTR, and SRV records.
- **Custom DNS Resolvers:** Specify custom DNS resolver IPs for your queries.
- **Graphviz Integration:** Export DNS resolution results as Graphviz `.gv` and `.pdf` diagrams.
- **Error Logging:** Comprehensive error logging for troubleshooting.
- **GPLv3 Licensed:** Open-source under the GNU General Public License v3.

## Installation

### Prerequisites

- **Python 3.7+** must be installed on your system.
- **Graphviz** must be installed and added to your system's PATH.

### Automatic Setup on macOS and Linux

nstree can be installed as a system tool using the provided setup script. Run the following commands:

```bash
curl -O https://raw.githubusercontent.com/atenreiro/nstree/main/setup.sh
chmod +x setup.sh
sudo ./setup.sh
```

This will install `nstree` and make it accessible as a system command.

### Clone the Repository

```bash
git clone https://github.com/atenreiro/nstree.git
cd nstree
```

### Install Dependencies

It's recommended to use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

*Note: Ensure that `dnspython` and `graphviz` are listed in your `requirements.txt`.*

## Usage

```bash
python3 nstree.py [OPTIONS] DOMAIN [DOMAIN ...]
```

### Arguments

- `DOMAIN`: One or more domains to resolve.

### Options

- `-t, --record-types`: Specify DNS record types to query. Supported types:
  - `A`, `MX`, `CNAME`, `NS`, `TXT`, `AAAA`, `SOA`, `PTR`, `SRV`
  - **Default:** `A`

- `-r, --resolver`: Specify a custom DNS resolver IP (e.g., `8.8.8.8`).

- `--export`: Export the DNS resolution results as Graphviz diagrams (`.gv` and `.pdf` files).

- `-v, --version`: Show the tool's version and exit.

### Examples

1. **Basic DNS A Record Query:**

   ```bash
   python3 nstree.py example.com
   ```

2. **Query Multiple Domains with Specific Record Types:**

   ```bash
   python3 nstree.py example.com opensquat.com -t A MX CNAME
   ```

3. **Use a Custom DNS Resolver and Export Results:**

   ```bash
   python3 nstree.py example.com -r 8.8.8.8 --export
   ```

4. **Query Multiple Domains with All Supported Record Types:**

   ```bash
   python3 nstree.py example.com opensquat.com -t A MX CNAME NS TXT AAAA SOA PTR SRV
   ```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author
Developed by [Andre Tenreiro](https://www.linkedin.com/in/andretenreiro/).

For any questions, please feel free to reach out or open an issue on the GitHub repository.
