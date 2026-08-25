import './globals.css';

export const metadata = {
  title: 'AegisX Security Platform v55',
  description: 'AI-powered Web, API, SCA, LLM, RAG and Agent security testing platform'
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
