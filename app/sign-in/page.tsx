import { buildIdentityStartURL, safeReturnPath } from "../auth/browser-flow";

export default async function SignInPage({ searchParams }: { searchParams: Promise<{ return_to?: string | string[] }> }) {
	const query = await searchParams;
	const returnTo = safeReturnPath(typeof query.return_to === "string" ? query.return_to : undefined);
	const target = buildIdentityStartURL(returnTo);
  return <main className="page">
    <h1>Sign in to Zasp</h1>
    <p>Continue through the configured identity provider.</p>
		<a href={target}>Continue to sign in</a>
  </main>;
}
