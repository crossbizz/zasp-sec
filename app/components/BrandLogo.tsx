/** Supplied blue and white wordmarks, selected by the app's theme. */
export function BrandLogo() {
  // Local SVG viewports frame the original PNG artwork without raster modification.
  /* eslint-disable @next/next/no-img-element */
  return <span className="brand-logo" aria-hidden="true">
    <img className="brand-logo__light" src="/brand/zasp-wordmark-light.svg" width={96} height={42} alt="" />
    <img className="brand-logo__dark" src="/brand/zasp-wordmark-dark.svg" width={96} height={42} alt="" />
  </span>;
}
