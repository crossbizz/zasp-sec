import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Zasp — Agent Security",
  description: "Discover, govern, protect, and test every agentic system from one security graph.",
  openGraph: {
    title: "Zasp — Agent Security",
    description: "Secure every agent. Discover assets, govern identities, enforce runtime guardrails, and adversarially test agentic systems.",
    type: "website",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "Zasp — Secure every agent." }],
  },
  twitter: {
    card: "summary_large_image",
    title: "Zasp — Agent Security",
    description: "Secure every agent.",
    images: ["/og.png"],
  },
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
