# WSL2 Kali Linux Setup Guide

## Prerequisites

1. **Windows 10/11** with WSL2 support
2. **Docker Desktop** (optional, for containerized approach)

## Step 1: Install WSL2

```powershell
# Open PowerShell as Administrator and run:
wsl --install

# Restart your computer when prompted
```

## Step 2: Install Kali Linux on WSL2

```powershell
# List available distributions
wsl --list --online

# Install Kali Linux
wsl --install -d kali-linux

# Or download from Microsoft Store: "Kali Linux"
```

## Step 3: Access Kali Linux

```bash
# Open Kali Linux terminal
kali

# Or from PowerShell
wsl -d kali-linux
```

## Step 4: Update Kali Linux

```bash
# Update package list
sudo apt update && sudo apt upgrade -y

# Install additional tools
sudo apt install -y git python3-pip python3-venv build-essential
```

## Step 5: Transfer Your Project

### Option A: Clone from Git
```bash
# In Kali Linux terminal
git clone <your-repo-url> Kai
cd Kai
```

### Option B: Copy from Windows
```bash
# From Windows, copy your project to WSL
# The WSL filesystem is accessible at: \\wsl$\kali-linux\home\kali\

# Or use WSL command from Windows PowerShell:
wsl cp -r C:\Users\ACER\Desktop\projects\Kai ~/Kai
```

## Step 6: Install Dependencies

```bash
# Navigate to project directory
cd ~/Kai

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

## Step 7: Install Kali Tools

```bash
# Install essential tools
sudo apt install -y nmap masscan subfinder amass httpx nuclei ffuf gobuster sqlmap nikto wpscan dirb theharvester dnsrecon wafw00f whatweb

# Install Go (if not already installed)
sudo apt install -y golang-go

# Install Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## Step 8: Run the Application

```bash
# Make sure you're in the project directory
cd ~/Kai

# Activate virtual environment
source venv/bin/activate

# Run the application
python main.py
```

## Step 9: Access from Windows

The application will be accessible from your Windows browser at:
- http://localhost:8000

## WSL2 Performance Tips

### 1. Configure WSL2 Memory Limits
Create `%UserProfile%\.wslconfig` in Windows:

```ini
[wsl2]
memory=8GB
processors=4
swap=2GB
localhostForwarding=true
```

### 2. Optimize File System Performance
```bash
# In Kali Linux, mount with performance options
sudo mount -t drvfs C: /mnt/c -o metadata,uid=1000,gid=1000,umask=22,fmask=111
```

### 3. Use WSL2 Native Filesystem
Keep your project in the WSL2 filesystem (`/home/kali/`) rather than the Windows filesystem for better performance.

## Troubleshooting WSL2

### Common Issues:

1. **WSL2 Not Starting**:
   ```powershell
   # Reset WSL2
   wsl --shutdown
   wsl --unregister kali-linux
   wsl --install -d kali-linux
   ```

2. **Network Issues**:
   ```bash
   # Check network connectivity
   ping google.com
   
   # Reset network
   sudo service networking restart
   ```

3. **Permission Issues**:
   ```bash
   # Fix ownership
   sudo chown -R kali:kali ~/Kai
   ```

4. **Port Forwarding Issues**:
   ```powershell
   # Check if port 8000 is accessible from Windows
   netstat -an | findstr :8000
   ```

## Alternative: Docker Approach

If you prefer using Docker:

```bash
# Install Docker in WSL2
sudo apt install -y docker.io

# Start Docker service
sudo service docker start

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM kalilinux/kali-rolling

RUN apt update && apt install -y \
    python3 python3-pip git \
    nmap masscan subfinder amass httpx nuclei ffuf gobuster \
    sqlmap nikto wpscan dirb theharvester dnsrecon wafw00f whatweb

WORKDIR /app
COPY . .

RUN pip3 install -r requirements.txt

EXPOSE 8000

CMD ["python3", "main.py"]
EOF

# Build and run
docker build -t kai-bug-hunter .
docker run -p 8000:8000 kai-bug-hunter
```

## Integration with Windows

### VS Code Integration:
1. Install "Remote - WSL" extension
2. Open VS Code in WSL: `code .` (from Kali terminal)
3. Develop directly in the Linux environment

### File Sharing:
- Windows files: `/mnt/c/Users/ACER/Desktop/`
- WSL files: `\\wsl$\kali-linux\home\kali\`

### GUI Applications:
```bash
# Install GUI support (if needed)
sudo apt install -y kali-linux-default kali-desktop-xfce

# Launch GUI from Windows
wsl -d kali-linux -e startxfce4
```

## Security Notes

1. **WSL2 Isolation**: WSL2 provides good isolation from Windows
2. **Network**: WSL2 has its own network stack
3. **File System**: Keep sensitive data in WSL2 filesystem
4. **Updates**: Regularly update both Windows and Kali Linux

## Performance Comparison

| Environment | Performance | Setup Complexity | Tool Availability |
|-------------|-------------|------------------|-------------------|
| Native Kali | Excellent | Medium | Full |
| WSL2 | Good | Low | Full |
| Docker | Good | Medium | Full |
| Windows | Poor | Low | Limited |

WSL2 provides the best balance of performance and ease of setup for Windows users. 