"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchDeviceReadings } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { format } from "date-fns";
import { Gauge, Heart, Activity, Thermometer, Stethoscope } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  TooltipProvider,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const ReadingIcon = {
  heartRate: Heart,
  bloodPressure: Activity,
  bodyTemperature: Thermometer,
  spo2: Gauge,
  respiratoryRate: Stethoscope,
  default: Gauge,
};

const ReadingUnit = {
  heartRate: "bpm",
  bloodPressure: "mmHg",
  bodyTemperature: "°C",
  spo2: "%",
  respiratoryRate: "breaths/min",
  default: "",
};

const ReadingRanges = {
  heartRate: { min: 40, max: 200, warning: { min: 60, max: 100 } },
  bloodPressure: { min: 70, max: 200, warning: { min: 90, max: 140 } },
  bodyTemperature: { min: 35, max: 42, warning: { min: 36.5, max: 37.5 } },
  spo2: { min: 80, max: 100, warning: { min: 95, max: 100 } },
  respiratoryRate: { min: 8, max: 30, warning: { min: 12, max: 20 } },
};

interface DeviceReadingsProps {
  deviceId: string;
}

export function DeviceReadings({ deviceId }: DeviceReadingsProps) {
  const { data } = useQuery({
    queryKey: ["device-readings", deviceId],
    queryFn: () => fetchDeviceReadings(deviceId),
    refetchInterval: 1000,
  });

  if (!data?.readings.length) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <p className="text-muted-foreground">No readings available</p>
        </CardContent>
      </Card>
    );
  }

  const latestReading = data.readings[0];
  const readingTypes = Object.keys(latestReading.readings);

  const getValue = (type: string, value: number) => {
    const range = ReadingRanges[type as keyof typeof ReadingRanges];
    if (!range) return "normal";
    
    if (value < range.warning.min || value > range.warning.max) {
      return "warning";
    }
    if (value < range.min || value > range.max) {
      return "critical";
    }
    return "normal";
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {readingTypes.map((type) => {
          const Icon = ReadingIcon[type as keyof typeof ReadingIcon] || ReadingIcon.default;
          return (
            <Card key={type}>
              <CardContent className="pt-6">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger>
                      <div className="flex items-center space-x-2">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                        <h3 className="text-sm font-medium text-muted-foreground capitalize">
                          {type.replace(/([A-Z])/g, ' $1').trim()}
                        </h3>
                      </div>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>Normal range: {ReadingRanges[type as keyof typeof ReadingRanges]?.warning.min} 
                        - {ReadingRanges[type as keyof typeof ReadingRanges]?.warning.max} 
                        {ReadingUnit[type as keyof typeof ReadingUnit]}
                      </p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                <div className="mt-2">
                  <p className={cn(
                    "text-2xl font-bold",
                    getValue(type, latestReading.readings[type]) === "warning" && "text-yellow-500",
                    getValue(type, latestReading.readings[type]) === "critical" && "text-red-500"
                  )}>
                    {latestReading.readings[type].toFixed(2)}
                    <span className="text-sm text-muted-foreground ml-1">
                      {ReadingUnit[type as keyof typeof ReadingUnit] || ReadingUnit.default}
                    </span>
                  </p>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Historical Data</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[400px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart 
                data={[...data.readings].map(reading => ({
                  timestamp: Math.floor(Number(reading.timestamp) / 1000) * 1000,
                  ...reading.readings
                })).reverse()}
              >
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={(value) => {
                    try {
                      return format(new Date(value), "HH:mm:ss");
                    } catch (e) {
                      console.error('Error formatting timestamp:', value, e);
                      return '';
                    }
                  }}
                  className="text-muted-foreground"
                />
                <YAxis className="text-muted-foreground" />
                <Tooltip
                  labelFormatter={(value) => {
                    try {
                      return format(new Date(value), "HH:mm:ss");
                    } catch (e) {
                      console.error('Error formatting timestamp:', value, e);
                      return '';
                    }
                  }}
                  contentStyle={{
                    backgroundColor: "hsl(var(--background))",
                    border: "1px solid hsl(var(--border))",
                  }}
                />
                <Legend />
                {readingTypes.map((type, index) => (
                  <Line
                    key={type}
                    type="monotone"
                    dataKey={type}
                    name={type.replace(/([A-Z])/g, ' $1').trim()}
                    stroke={`hsl(${index * 137.5}, 70%, 50%)`}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  );
} 