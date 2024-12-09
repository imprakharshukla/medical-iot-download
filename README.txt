MOBILE EDGE COMPUTING (MEC) PROJECT
==================================

PACKAGE CONTENTS
---------------
code.zip contains:
- mec.exe     (Edge Computing Server)
- device.exe  (IoT Device Simulator)

QUICK START GUIDE
----------------

1. EXTRACT FILES
   - Extract code.zip to a folder
   - You should see mec.exe and device.exe

2. START REDIS (Required)
   Run this command in terminal/command prompt:
   > docker run -d --name redis -p 6379:6379 redis:latest

3. START MEC SERVER
   > Double-click mec.exe
   > Wait for "Server instance created successfully" message

4. START DEVICE
   > Double-click device.exe for default medical sensor
   OR
   > Run with custom parameters:
   > device.exe --device-type="medical" --capabilities="heartRate,bloodPressure"

EXAMPLE DEVICE CONFIGURATIONS
---------------------------
Medical device:
> device.exe --device-type="medical" --capabilities="heartRate,bloodPressure,spo2"

Environmental sensor:
> device.exe --device-type="environmental" --capabilities="temperature,humidity"

AVAILABLE DEVICE TYPES
--------------------
- medical
- environmental
- industrial
- sensor

AVAILABLE CAPABILITIES
--------------------
- heartRate         (60-100 bpm)
- bloodPressure     (90-140 mmHg)
- bodyTemperature   (36.5-37.5°C)
- spo2             (95-100%)
- respiratoryRate   (12-20 breaths/min)
- ecg              (-0.5 to 0.5 mV)

NETWORK INFORMATION
-----------------
- MEC Server Port: 8080
- Redis Port: 6379
- Discovery Port: 1900
- Multicast Address: 239.255.255.250

TROUBLESHOOTING
-------------
1. If devices can't find server:
   - Check if Redis is running
   - Verify firewall isn't blocking ports
   - Ensure multicast is enabled on network

2. If "Redis connection refused":
   - Make sure Redis container is running
   - Check if port 6379 is available

3. If "Address already in use":
   - Another program is using required ports
   - Close other applications or change ports

REQUIREMENTS
-----------
- Windows 10 or later
- Docker Desktop installed (for Redis)
- Network connection
- Administrator privileges may be required

For additional help or issues, please refer to the project documentation.