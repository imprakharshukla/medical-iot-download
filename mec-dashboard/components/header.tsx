import { SystemStatus } from "@/app/features/components/systemStatus";
import { ModeToggle } from "@/components/mode-toggle";
import { Cpu } from "lucide-react";

export function Header() {
  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 p-4">
      <div className="container flex h-14 items-center">
        <div className="flex items-center space-x-2">
          <Cpu className="h-6 w-6" />
          <span className="font-bold">MEC Dashboard</span>
        </div>
        <div className="flex flex-1 items-center justify-end space-x-4">
          <SystemStatus />
          <ModeToggle />
        </div>
      </div>
    </header>
  );
} 