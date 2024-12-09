import axios from 'axios';

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080',
  timeout: 5000,
});

// Add response interceptor for better error handling
api.interceptors.response.use(
  response => response,
  error => {
    console.error('API Error:', error);
    if (error.response?.status === 404) {
      console.error('API endpoint not found:', error.config.url);
    }
    return Promise.reject(error);
  }
);

export interface Device {
  device_id: string;
  device_type: string;
  status: 'Online' | 'Offline';
  last_seen: string;
  capabilities: string[];
}

export interface Reading {
  timestamp: string;
  type: string;
  reading_count: number;
  readings: {
    [key: string]: number;
  };
}

export interface DeviceReadings {
  device_id: string;
  readings: Reading[];
}

export const fetchDevices = async (): Promise<Device[]> => {
  const { data } = await api.get('/api/devices');
  return data;
};

export const fetchDeviceReadings = async (deviceId: string): Promise<DeviceReadings> => {
  const { data } = await api.get(`/api/devices/${deviceId}/data`);
  return data;
};

export const fetchSystemStatus = async () => {
  const { data } = await api.get('/api/status');
  return data;
};