import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      { source: "/remote", destination: "/mobile" },
      { source: "/agent/:path*", destination: "/api/agent/:path*" },
      { source: "/devices/:path*", destination: "/api/devices/:path*" },
      { source: "/commands/:path*", destination: "/api/commands/:path*" },
      { source: "/commands", destination: "/api/commands" },
      { source: "/pair", destination: "/api/pair" },
      { source: "/history", destination: "/api/history" },
      { source: "/status", destination: "/api/status" },
    ];
  },
};

export default nextConfig;
