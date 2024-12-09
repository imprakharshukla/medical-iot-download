"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchDeviceReadings } from "../../../lib/api";
import { Card, CardHeader, CardTitle, CardContent } from "../../../components/ui/card";
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

interface DeviceReadingsProps {
  deviceId: string;
}

interface Reading {
  timestamp: string;
  readings: {
    [key: string]: number;
  };
}

interface DeviceData {
  device_id: string;
  readings: Reading[];
}

export function DeviceReadings({ deviceId }: DeviceReadingsProps) {
  const { data, isLoading, error } = useQuery<DeviceData>({
    queryKey: ["device-readings", deviceId],
    queryFn: () => fetchDeviceReadings(deviceId),
    refetchInterval: 5000,
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <p className="text-muted-foreground">Loading readings...</p>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <p className="text-red-500">Error loading readings</p>
        </CardContent>
      </Card>
    );
  }

  if (!data?.readings?.length) {
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

  // Process data for the chart
  console.log('Raw readings:', data.readings);
  const chartData = data.readings
    .map((reading: Reading) => {
      // Convert milliseconds to seconds for the timestamp
      const timestamp = Math.floor(Number(reading.timestamp) / 1000) * 1000;
      if (isNaN(timestamp)) {
        console.error('Invalid timestamp:', reading.timestamp);
        return null;
      }
      return {
        timestamp,
        ...reading.readings,
      };
    })
    .filter(Boolean)
    .reverse();
  console.log('Processed chart data:', chartData);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Device Readings - {deviceId}</CardTitle>
      </CardHeader>
      <CardContent>
        {/* Latest readings display */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          {readingTypes.map((type) => (
            <Card key={type}>
              <CardContent className="p-4">
                <p className="text-sm text-muted-foreground capitalize">
                  {type.replace(/([A-Z])/g, ' $1').trim()}
                </p>
                <p className="text-2xl font-bold">
                  {latestReading.readings[type].toFixed(2)}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Historical chart */}
        <div className="h-[400px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              {/* <XAxis
                dataKey="timestamp"
                type="number"
                domain={['auto', 'auto']}
               
              /> */}
              <YAxis />
              <Tooltip
                // labelFormatter={(value) => {
                //   try {
                //     const date = new Date(value);
                //     if (isNaN(date.getTime())) {
                //       console.error('Invalid tooltip value:', value);
                //       return '';
                //     }
                //     return format(date, "HH:mm:ss");
                //   } catch (e) {
                //     console.error('Error formatting tooltip timestamp:', value, e);
                //     return '';
                //   }
                // }}
                contentStyle={{ backgroundColor: 'rgba(0, 0, 0, 0.8)', border: 'none' }}
                itemStyle={{ color: '#fff' }}
              />
              <Legend />
              {readingTypes.map((type, index) => (
                <Line
                  key={type}
                  type="monotone"
                  dataKey={type}
                  name={type.replace(/([A-Z])/g, ' $1').trim()}
                  stroke={`hsl(${index * 137.5}, 70%, 50%)`}
                  dot={false}
                  isAnimationActive={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}