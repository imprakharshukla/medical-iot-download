"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Activity } from "lucide-react";
import { DeviceList } from "./features/components/deviceList";
import { DeviceReadings } from "@/components/device-readings";

export default function Home() {
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null);

  return (
    <main className="container p-6">
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        <div className="md:col-span-3 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Activity className="h-5 w-5" />
                <span>Device Monitor</span>
              </CardTitle>
              <CardDescription>
                Connected devices and their status
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <DeviceList
                selectedDevice={selectedDevice}
                onDeviceSelect={setSelectedDevice}
              />
            </CardContent>
          </Card>
        </div>
        <div className="md:col-span-9">
          {selectedDevice ? (
            <DeviceReadings deviceId={selectedDevice} />
          ) : (
            <Card>
              <CardContent className="min-h-[400px] flex items-center justify-center">
                <p className="text-muted-foreground">
                  Select a device to view readings
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </main>
  );
}