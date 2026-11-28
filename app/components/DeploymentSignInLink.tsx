export function DeploymentSignInLink() {
  // A full navigation discards the tenant runtime before entering operator sign-in.
  // eslint-disable-next-line @next/next/no-html-link-for-pages
  return <a href="/deployment-admin">Deployment Administrator sign-in</a>;
}
