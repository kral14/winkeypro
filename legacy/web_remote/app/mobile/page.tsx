import type { Metadata } from "next";
import MobileRemote from "./remote";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "WinKey — Mobil İdarəetmə",
  referrer: "no-referrer",
  robots: { index: false, follow: false }
};

export default async function MobilePage({
  searchParams
}: {
  searchParams: Promise<{ device?: string; code?: string }>;
}) {
  const p = await searchParams;
  return <MobileRemote initialDevice={p.device || ""} pairCode={p.code || ""} />;
}
