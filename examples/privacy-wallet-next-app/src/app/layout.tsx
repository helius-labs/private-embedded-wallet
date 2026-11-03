import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
// One import pulls in everything helius-wallet-kit needs — the stylesheet
// bundles the wallet UI styles. Next.js disallows global CSS imports inside
// library modules, so this stays at the layout level.
import "helius-wallet-kit/ui/styles.css";
import "./globals.css";
import { Providers } from "./providers";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Zolana Privacy Wallet",
  description:
    "An attested enclave holds private-wallet keys and authorizes private Solana transactions.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
