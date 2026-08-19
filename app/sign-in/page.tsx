import { buildIdentityStartURL, safeReturnPath } from "../auth/browser-flow";

export default async function SignInPage({ searchParams }: { searchParams: Promise<{ return_to?: string | string[] }> }) {
	const query = await searchParams;
	const returnTo = safeReturnPath(typeof query.return_to === "string" ? query.return_to : undefined);
	const target = buildIdentityStartURL(process.env.NEXT_PUBLIC_ZASP_IDENTITY_START_URL, returnTo);
  return <main className="page">
    <h1>Sign in to Zasp</h1>
    <p>Continue through the configured identity provider.</p>
		{target ? <a href={target}>Continue to sign in</a> : <p role="alert">Sign-in provider is unavailable.</p>}
  </main>;
}
