#!/bin/bash
# UDTUN Server Setup Script
# Complete one-shot installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root"
        exit 1
    fi
}

check_dependencies() {
    print_info "Checking dependencies..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_info "Installing Python3..."
        apt-get update
        apt-get install -y python3 python3-pip
    fi
    
    # Check iptables
    if ! command -v iptables &> /dev/null; then
        print_info "Installing iptables..."
        apt-get install -y iptables
    fi
    
    # Check net-tools for ifconfig
    if ! command -v ifconfig &> /dev/null; then
        print_info "Installing net-tools..."
        apt-get install -y net-tools
    fi
    
    print_success "Dependencies checked"
}

setup_directories() {
    print_info "Setting up directories..."
    
    # Create main directory
    mkdir -p /opt/udtun/server
    
    # Create log directory
    mkdir -p /var/log/udtun
    
    # Create config directory
    mkdir -p /etc/udtun
    
    # Create systemd directory
    mkdir -p /etc/systemd/system
    
    print_success "Directories created"
}

copy_files() {
    print_info "Copying server files..."
    
    # Get script directory
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    SERVER_DIR="$(dirname "$SCRIPT_DIR")"
    
    # Copy source files
    cp -r "$SERVER_DIR/src/" /opt/udtun/server/
    
    # Make Python files executable
    chmod +x /opt/udtun/server/main.py
    chmod +x /opt/udtun/server/*.py
    
    print_success "Files copied"
}

create_config() {
    print_info "Creating configuration..."
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    # Create server config
    cat > /etc/udtun/server.json << EOF
{
    "udp_port_range": [6000, 19999],
    "listen_port": 5667,
    "bind_ip": "0.0.0.0",
    "tun_name": "udtun0",
    "tun_ip": "10.9.0.1",
    "tun_netmask": "255.255.255.0",
    "tun_mtu": 1300,
    "session_timeout": 30,
    "keepalive_interval": 10,
    "max_clients": 1000,
    "udp_buffer_size": 4194304,
    "max_packet_size": 1500,
    "read_timeout": 0.01,
    "enable_rate_limit": true,
    "rate_limit_per_client": 1000,
    "log_file": "/var/log/udtun/server.log",
    "log_level": "INFO"
}
EOF
    
    print_success "Configuration created"
    
    # Show config
    echo ""
    print_info "Server Configuration:"
    echo "========================="
    echo "Server IP: $SERVER_IP"
    echo "UDP Ports: 6000-19999"
    echo "Listening Port: 5667"
    echo "TUN Network: 10.9.0.1/24"
    echo "Config File: /etc/udtun/server.json"
    echo ""
}

setup_systemd() {
    print_info "Setting up systemd service..."
    
    # Create systemd service file
    cat > /etc/systemd/system/udtun-server.service << EOF
[Unit]
Description=UDTUN UDP Tunneling Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/udtun/server
ExecStart=/usr/bin/python3 /opt/udtun/server/main.py /etc/udtun/server.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=udtun-server

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/udtun

# Performance
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable udtun-server.service
    
    print_success "Systemd service configured"
}

setup_kernel_modules() {
    print_info "Setting up kernel modules..."
    
    # Load TUN module
    modprobe tun 2>/dev/null || true
    
    # Make sure module loads on boot
    echo "tun" >> /etc/modules-load.d/tun.conf
    
    # Check if /dev/net/tun exists
    if [ ! -c /dev/net/tun ]; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200
        chmod 666 /dev/net/tun
    fi
    
    print_success "Kernel modules configured"
}

setup_sysctl() {
    print_info "Configuring sysctl parameters..."
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    
    # Increase UDP buffer sizes
    echo "net.core.rmem_max=4194304" >> /etc/sysctl.conf
    echo "net.core.wmem_max=4194304" >> /etc/sysctl.conf
    echo "net.core.rmem_default=262144" >> /etc/sysctl.conf
    echo "net.core.wmem_default=262144" >> /etc/sysctl.conf
    
    # Apply changes
    sysctl -p
    
    print_success "Sysctl configured"
}

setup_firewall() {
    print_info "Configuring firewall..."
    
    # Get external interface
    EXT_IF=$(ip route | grep default | awk '{print $5}' | head -1)
    
    if [ -z "$EXT_IF" ]; then
        print_warning "Could not determine external interface"
        return
    fi
    
    # Disable UFW if it's running (we'll use iptables directly)
    if systemctl is-active --quiet ufw; then
        print_info "Disabling UFW..."
        ufw --force disable
    fi
    
    # Basic iptables rules (server.py will add more)
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow ICMP
    iptables -A INPUT -p icmp -j ACCEPT
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    
    print_success "Firewall configured"
}

start_service() {
    print_info "Starting UDTUN service..."
    
    # Start service
    systemctl start udtun-server.service
    
    # Check status
    sleep 2
    systemctl status udtun-server.service --no-pager
    
    print_success "Service started"
}

show_summary() {
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "=" * 60
    echo "UDTUN SERVER INSTALLATION COMPLETE"
    echo "=" * 60
    echo ""
    echo "Server Information:"
    echo "-------------------"
    echo "Server IP:        $SERVER_IP"
    echo "UDP Port Range:   6000-19999"
    echo "Listening Port:   5667"
    echo "TUN Network:      10.9.0.1/24"
    echo "Config File:      /etc/udtun/server.json"
    echo "Log File:         /var/log/udtun/server.log"
    echo ""
    echo "Service Commands:"
    echo "-----------------"
    echo "Start:            systemctl start udtun-server"
    echo "Stop:             systemctl stop udtun-server"
    echo "Restart:          systemctl restart udtun-server"
    echo "Status:           systemctl status udtun-server"
    echo "Logs:             journalctl -u udtun-server -f"
    echo ""
    echo "Testing:"
    echo "-------"
    echo "Test server:      python3 /opt/udtun/server/main.py"
    echo "Check TUN:        ip addr show udtun0"
    echo "Check iptables:   iptables -L -n -v"
    echo "                  iptables -t nat -L -n -v"
    echo ""
    echo "Client Configuration:"
    echo "--------------------"
    echo "Set server_ip to: $SERVER_IP in client config"
    echo ""
    echo "=" * 60
}

main() {
    print_info "Starting UDTUN Server Installation"
    print_info "Date: $(date)"
    print_info "System: $(uname -a)"
    echo ""
    
    # Check root
    check_root
    
    # Check dependencies
    check_dependencies
    
    # Setup directories
    setup_directories
    
    # Copy files
    copy_files
    
    # Create config
    create_config
    
    # Setup kernel modules
    setup_kernel_modules
    
    # Setup sysctl
    setup_sysctl
    
    # Setup firewall
    setup_firewall
    
    # Setup systemd
    setup_systemd
    
    # Start service
    start_service
    
    # Show summary
    show_summary
    
    print_success "Installation completed successfully!"
}

# Run main function
main
