import type { ReactNode } from "react";
import { ThemeControl } from "./ThemeControl";

export function AuthPage({ children }: { children: ReactNode }) {
  return <main className="page auth-page"><div className="auth-appearance"><ThemeControl /></div>{children}</main>;
}
