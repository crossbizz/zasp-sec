import surfaces from "../../../services/platform/compliancemap/surfaces.json";

type Applicability = "applicable" | "unassessed" | "out_of_scope";
const statuses = { applicable: "Applicable", unassessed: "Unassessed", out_of_scope: "Out of scope" };

export function FrameworkSurfaceReview({scope, applicability}: {scope: string; applicability: Applicability}) {
  const reviewed = new Set(scope.split(","));
  const known = new Set(surfaces.map(s => s.id));
  if ([...reviewed].some(surface => !known.has(surface))) return null;
  return <details>
    <summary>Applicability by product surface</summary>
    <table>
      <caption>Release scope by surface. Evidence totals cover the category across this Environment.</caption>
      <thead><tr><th scope="col">Product surface</th><th scope="col">Review status</th></tr></thead>
      <tbody>{surfaces.map(surface => <tr key={surface.id}>
        <th scope="row">{surface.label}</th>
        <td>{statuses[reviewed.has(surface.id) ? applicability : "unassessed"]}</td>
      </tr>)}</tbody>
    </table>
  </details>;
}
