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
    
    # Copy source files from src/ to /opt/udtun/server/
    if [ -d "$SERVER_DIR/src" ]; then
        cp -r "$SERVER_DIR/src/"* /opt/udtun/server/
    else
        # Fallback: copy everything except scripts
        find "$SERVER_DIR" -type f -name "*.py" | while read -r file; do
            if [[ ! "$file" =~ scripts/ ]]; then
                cp "$file" /opt/udtun/server/
            fi
        done
    fi
    
    # Make Python files executable
    find /opt/udtun/server -name "*.py" -type f -exec chmod +x {} \;
    
    print_success "Files copied to /opt/udtun/server/"
}

create_config() {
    print_info "Creating configuration..."
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="0.0.0.0"
    fi
    
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
    cat > /etc/systemd/system/udtun-server.service << 'EOF'
[Unit]
Description=UDTUN UDP Tunneling Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/udtun/server
ExecStart=/usr/bin/python3 /opt/udtun/server/main.py /etc/udtun/server.json
ExecReload=/bin/kill -HUP $MAINPID
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
    systemctl enable udtun-server.service 2>/dev/null || true
    
    print_success "Systemd service configured"
}

setup_kernel_modules() {
    print_info "Setting up kernel modules..."
    
    # Load TUN module
    modprobe tun 2>/dev/null || true
    
    # Make sure module loads on boot
    if [ -d /etc/modules-load.d ]; then
        echo "tun" > /etc/modules-load.d/tun.conf
    else
        echo "tun" >> /etc/modules
    fi
    
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
    
    # Backup original sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.backup 2>/dev/null || true
    
    # Enable IP forwarding
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    # Increase UDP buffer sizes
    for param in net.core.rmem_max net.core.wmem_max net.core.rmem_default net.core.wmem_default; do
        if ! grep -q "$param" /etc/sysctl.conf; then
            case $param in
                net.core.rmem_max) echo "$param=4194304" >> /etc/sysctl.conf ;;
                net.core.wmem_max) echo "$param=4194304" >> /etc/sysctl.conf ;;
                net.core.rmem_default) echo "$param=262144" >> /etc/sysctl.conf ;;
                net.core.wmem_default) echo "$param=262144" >> /etc/sysctl.conf ;;
            esac
        fi
    done
    
    # Apply changes
    sysctl -p 2>/dev/null || true
    
    print_success "Sysctl configured"
}

setup_firewall() {
    print_info "Configuring firewall..."
    
    # Get external interface
    EXT_IF=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$EXT_IF" ]; then
        print_warning "Could not determine external interface"
        EXT_IF="eth0"
    fi
    
    # Disable UFW if it's running (we'll use iptables directly)
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        print_info "Disabling UFW..."
        ufw --force disable
    fi
    
    # Flush existing rules (careful!)
    print_info "Setting up iptables rules..."
    
    # Set default policies
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Flush all rules
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    iptables -X
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow ICMP (ping)
    iptables -A INPUT -p icmp -j ACCEPT
    
    # Allow UDP port range for UDTUN
    iptables -A INPUT -p udp --dport 6000:19999 -j ACCEPT
    
    # Allow listening port
    iptables -A INPUT -p udp --dport 5667 -j ACCEPT
    
    # DNAT: Redirect all UDP ports to our listening port
    iptables -t nat -A PREROUTING -p udp --dport 6000:19999 -j DNAT --to-destination :5667
    
    # NAT masquerade
    iptables -t nat -A POSTROUTING -o $EXT_IF -j MASQUERADE
    
    # Save rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    
    print_success "Firewall configured"
}

start_service() {
    print_info "Starting UDTUN service..."
    
    # Stop if already running
    systemctl stop udtun-server.service 2>/dev/null || true
    
    # Start service
    if systemctl start udtun-server.service; then
        sleep 2
        if systemctl is-active --quiet udtun-server.service; then
            print_success "Service started successfully"
            systemctl status udtun-server.service --no-pager
        else
            print_warning "Service started but not active. Check logs with: journalctl -u udtun-server"
        fi
    else
        print_warning "Failed to start service. Check manually with: python3 /opt/udtun/server/main.py"
    fi
}

show_summary() {
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="$(ip addr show | grep -oP 'inet \K[\d.]+' | grep -v 127.0.0.1 | head -1)"
    fi
    
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
    echo "Install Dir:      /opt/udtun/server/"
    echo ""
    echo "Service Commands:"
    echo "-----------------"
    echo "Start:            systemctl start udtun-server"
    echo "Stop:             systemctl stop udtun-server"
    echo "Restart:          systemctl restart udtun-server"
    echo "Status:           systemctl status udtun-server"
    echo "Logs:             journalctl -u udtun-server -f"
    echo ""
    echo "Manual Testing:"
    echo "--------------"
    echo "Test server:      cd /opt/udtun/server && python3 main.py"
    echo "Check TUN:        ip addr show udtun0"
    echo "Check iptables:   iptables -L -n -v"
    echo "                  iptables -t nat -L -n -v"
    echo ""
    echo "Troubleshooting:"
    echo "----------------"
    echo "Check logs:       tail -f /var/log/udtun/server.log"
    echo "Test ports:       nc -z -u localhost 5667"
    echo "Check TUN device: ls -la /dev/net/tun"
    echo ""
    echo "Client Configuration:"
    echo "--------------------"
    echo "Set server_ip to: $SERVER_IP in client config"
    echo ""
    echo "=" * 60
}

test_installation() {
    print_info "Testing installation..."
    
    # Check if main.py exists
    if [ ! -f /opt/udtun/server/main.py ]; then
        print_error "main.py not found in /opt/udtun/server/"
        ls -la /opt/udtun/server/
        return 1
    fi
    
    # Check if config exists
    if [ ! -f /etc/udtun/server.json ]; then
        print_error "Config file not found: /etc/udtun/server.json"
        return 1
    fi
    
    # Check Python syntax
    if ! python3 -m py_compile /opt/udtun/server/main.py 2>/dev/null; then
        print_warning "Python syntax check failed for main.py"
    fi
    
    print_success "Installation test passed"
    return 0
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
    
    # Test file copy
    if [ ! -f /opt/udtun/server/main.py ]; then
        print_error "Failed to copy main.py. Manual copy needed."
        print_info "Manual copy: cp src/*.py /opt/udtun/server/"
        cp src/*.py /opt/udtun/server/ 2>/dev/null || true
        chmod +x /opt/udtun/server/*.py 2>/dev/null || true
    fi
    
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
    
    # Test installation
    test_installation
    
    # Start service
    start_service
    
    # Show summary
    show_summary
    
    print_success "Installation completed!"
    echo ""
    print_info "If service failed to start, try running manually:"
    echo "cd /opt/udtun/server && python3 main.py"
}

# Run main function
main "$@"
