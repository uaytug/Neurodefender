import { invoke } from '@tauri-apps/api/core';

// This interface defines the structure returned by the Rust command get_system_info
interface RustSystemInfo {
    deviceName: string;
    totalMemMB: number;
    usedMemMB: number;
    ramPercent: number;
    cpuPercent: number;
}

// This interface defines the structure that showSystemInfo will return to the frontend
export interface FrontendSystemInfo {
    deviceName: string;
    totalMem: number; // Total memory in MB
    freeMem: number;  // Free memory in MB
    usedMem: number;  // Used memory in MB
    ramUsagePercent: number;
    cpuUsage: number;
}

async function showSystemInfo(): Promise<FrontendSystemInfo> {
    try {
        // Type assertion for the data received from Rust
        const data = await invoke<RustSystemInfo>('get_system_info');

        return {
            deviceName: data.deviceName,
            totalMem: data.totalMemMB,
            freeMem: data.totalMemMB - data.usedMemMB, // Derived
            usedMem: data.usedMemMB,
            ramUsagePercent: data.ramPercent,
            cpuUsage: data.cpuPercent
        };
    } catch (error) {
        console.error("Failed to invoke get_system_info:", error);
        // Return a default/fallback structure in case of error
        return {
            deviceName: "Unknown",
            totalMem: 0,
            freeMem: 0,
            usedMem: 0,
            ramUsagePercent: 0,
            cpuUsage: 0
        };
    }
}

export default showSystemInfo;