"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchSystemStatus } from "../../../lib/api";
import { Badge } from "../../../components/ui/badge";

export function SystemStatus() {
  const { data } = useQuery({
    queryKey: ["system-status"],
    queryFn: fetchSystemStatus,
    refetchInterval: 5000,
  });

  const isHealthy = data?.status === "ok";

  return (
    <Badge variant={isHealthy ? "default" : "destructive"}>
      {isHealthy ? "System Healthy" : "System Error"}
    </Badge>
  );
}