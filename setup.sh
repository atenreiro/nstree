#!/bin/bash

# nstree Setup Script for macOS and Linux
# Developer: Andre Tenreiro
# Project URL: https://github.com/atenreiro/nstree

# Ensure the script is run with superuser privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or use sudo"
  exit 1
fi

# Install prerequisites
if command -v apt-get &> /dev/null; then
  # Debian/Ubuntu-based systems
  apt-get update
  apt-get install -y python3 python3-venv python3-pip graphviz
elif command -v yum &> /dev/null; then
  # RedHat/CentOS-based systems
  yum install -y python3 python3-venv python3-pip graphviz
elif command -v brew &> /dev/null; then
  # macOS
  brew install python3 graphviz
else
  echo "Unsupported package manager. Please install Python 3, pip, and Graphviz manually."
  exit 1
fi

# Clone the repository
INSTALL_DIR="/opt/nstree"
if [ -d "$INSTALL_DIR" ]; then
  echo "nstree is already installed in $INSTALL_DIR"
  exit 1
fi

git clone https://github.com/atenreiro/nstree.git "$INSTALL_DIR"
cd "$INSTALL_DIR" || exit 1

# Set up virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate

# Create a symbolic link to make nstree globally accessible
ln -s "$INSTALL_DIR/nstree.py" /usr/local/bin/nstree
chmod +x /usr/local/bin/nstree

# Print success message
echo "nstree has been successfully installed. You can now use it as a system tool by running 'nstree'."
