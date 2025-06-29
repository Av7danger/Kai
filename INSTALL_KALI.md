# Kali Linux Installation Guide

## Prerequisites

1. **Kali Linux** (2024.1 or later recommended)
2. **Python 3.8+** (should be pre-installed)
3. **Git** (for cloning the repository)

## Step 1: Clone the Repository

```bash
# Clone the repository
git clone <your-repo-url> Kai
cd Kai

# Or if you're transferring files manually, navigate to the project directory
cd /path/to/Kai
```

## Step 2: Install Python Dependencies

```bash
# Update package list
sudo apt update

# Install Python pip if not already installed
sudo apt install -y python3-pip

# Install required system packages
sudo apt install -y python3-venv python3-dev build-essential

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

## Step 3: Install Kali Tools (Optional - Auto-installation)

The framework will automatically detect and install missing tools, but you can manually install common ones:

```bash
# Install essential reconnaissance tools
sudo apt install -y nmap masscan subfinder amass httpx nuclei ffuf gobuster

# Install exploitation tools
sudo apt install -y sqlmap nikto wpscan dirb

# Install additional tools
sudo apt install -y theharvester dnsrecon wafw00f whatweb

# Install Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
```

## Step 4: Configure Environment

```bash
# Create necessary directories
mkdir -p data/logs data/kali_results/exports data/kali_results/payloads data/kali_results/reports data/kali_results/scans

# Set permissions
chmod 755 data/
chmod 755 data/kali_results/

# Copy example configuration
cp agents.yml.example agents.yml
```

## Step 5: Run the Application

```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Run the application
python main.py
```

The server will start on `http://0.0.0.0:8000`

## Step 6: Access the Dashboard

Open your browser and navigate to:
- **Main Dashboard**: http://localhost:8000
- **Enhanced Dashboard**: http://localhost:8000/enhanced
- **Behind Scenes**: http://localhost:8000/behind-scenes

## Step 7: First Run Setup

1. **Tool Detection**: The system will automatically scan for available Kali tools
2. **Auto-Installation**: Use the dashboard to install missing tools
3. **Configuration**: Configure your target domains and scope

## Troubleshooting

### Common Issues:

1. **Permission Denied**:
   ```bash
   sudo chown -R $USER:$USER /path/to/Kai
   chmod +x main.py
   ```

2. **Port Already in Use**:
   ```bash
   # Find process using port 8000
   sudo netstat -tulpn | grep :8000
   
   # Kill the process
   sudo kill -9 <PID>
   ```

3. **Missing Dependencies**:
   ```bash
   # Reinstall requirements
   pip install --force-reinstall -r requirements.txt
   ```

4. **Tool Installation Issues**:
   ```bash
   # Update Kali repositories
   sudo apt update && sudo apt upgrade
   
   # Install build tools
   sudo apt install -y build-essential git
   ```

### Performance Optimization:

```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize system for security testing
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
```

## Security Considerations

1. **Firewall**: Configure firewall rules appropriately
2. **Permissions**: Run with appropriate user permissions
3. **Network**: Ensure you have permission to test target systems
4. **Legal**: Only test systems you own or have explicit permission to test

## Advanced Configuration

### Custom Tool Paths:
Edit `app/core/kali_optimizer.py` to add custom tool paths:

```python
'tools_config = {
    'custom_tool': {
        'required': False,
        'path': '/usr/local/bin/custom_tool',
        'version_check': 'custom_tool --version',
        'test_command': 'custom_tool --test'
    }
}
```

### Environment Variables:
```bash
export KAI_DEBUG=1
export KAI_LOG_LEVEL=DEBUG
export KAI_MAX_WORKERS=10
```

## Monitoring and Logs

- **Application Logs**: `data/bug_hunter.log`
- **Tool Output**: `data/kali_results/`
- **System Logs**: `journalctl -u kai-bug-hunter`

## Updates

```bash
# Update the application
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Restart the application
python main.py
```

## Support

For issues and questions:
1. Check the logs in `data/bug_hunter.log`
2. Review the API documentation at `http://localhost:8000/docs`
3. Check system status at `http://localhost:8000/api/system-status` 