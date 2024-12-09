"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchDevices } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useState } from "react";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";

interface DeviceListProps {
  selectedDevice: string | null;
  onDeviceSelect: (deviceId: string) => void;
}

export function DeviceList({ selectedDevice, onDeviceSelect }: DeviceListProps) {
  const [showOffline, setShowOffline] = useState(true);
  
  const { data: devices = [] } = useQuery({
    queryKey: ["devices"],
    queryFn: fetchDevices,
    refetchInterval: 5000,
  });

  const filteredDevices = showOffline 
    ? devices 
    : devices.filter(d => d.status === "Online");

  return (
    <div className="space-y-4">
      <div className="px-4 py-2 flex items-center space-x-2">
        <Switch
          id="show-offline"
          checked={showOffline}
          onCheckedChange={setShowOffline}
        />
        <Label htmlFor="show-offline">Show offline devices</Label>
      </div>
      
      <div className="divide-y">
        {filteredDevices.map((device) => (
          <button
            key={device.device_id}
            className={cn(
              "w-full px-4 py-3 flex items-center justify-between hover:bg-accent/50 transition-colors",
              selectedDevice === device.device_id && "bg-accent",
              device.status === "Offline" && "opacity-50"
            )}
            onClick={() => onDeviceSelect(device.device_id)}
            disabled={device.status === "Offline"}
          >
            <div className="text-left">
              <p className="font-medium">{device.device_type}</p>
              <p className="text-sm text-muted-foreground">
                {device.device_id}
              </p>
              {device.status === "Offline" && (
                <p className="text-xs text-muted-foreground">
                  Last seen: {new Date(device.last_seen).toLocaleString()}
                </p>
              )}
            </div>
            {device.status === "Online" ? (
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
              </span>
            ) : (
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
              </span>
            )}
          </button>
        ))}
        
        {filteredDevices.length === 0 && (
          <div className="p-4 text-center text-muted-foreground">
            No devices found
          </div>
        )}
      </div>
    </div>
  );
}