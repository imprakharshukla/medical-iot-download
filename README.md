# MOBILE EDGE COMPUTING (MEC) PROJECT

## Package Contents
`code.zip` contains:
- `mec.exe` - Edge Computing Server
- `device.exe` - IoT Device Simulator

## Quick Start Guide

### 1. Extract Files
- Extract `code.zip` to a folder
- You should see `mec.exe` and `device.exe`

### 2. Start Redis (Required)
Run this command in terminal/command prompt:
```
docker run -d --name redis -p 6379:6379 redis:latest
```

### 3. Start MEC Server
- Double-click `mec.exe`
- The MEC Server will start running

### 4. Start IoT Device Simulator
- Double-click `device.exe`
- The IoT Device Simulator will start running

### 5. Run the Simulation
- The simulation will start running
- The results will be displayed in the terminal

