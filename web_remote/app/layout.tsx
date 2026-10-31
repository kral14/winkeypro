import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { title: "WinKey — Kompüterin həmişə yanında", description: "Windows kompüterinin kilidini telefonundan aç.", manifest: "/manifest.webmanifest", icons: { icon: "/winkey.svg", apple: "/winkey.svg" } };
export default function Layout({children}: {children: React.ReactNode}) { return <html lang="az"><body>{children}</body></html> }
