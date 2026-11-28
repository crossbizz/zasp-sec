import type { Metadata } from "next";
import { DeploymentAdmin } from "./DeploymentAdmin";

export const metadata: Metadata = {
  title: "Deployment Administrator · Zasp",
  robots: { index: false, follow: false },
  referrer: "no-referrer",
};

export default function DeploymentAdminPage() {
  return <DeploymentAdmin />;
}
