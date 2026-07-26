import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "OSIRIS — Investigation Console",
  description: "Evidence-first OSINT investigation and explainability workspace.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
