import {copyFileSync,constants,existsSync,mkdirSync,readFileSync,statSync,writeFileSync} from "node:fs";
import path from "node:path";
import {evidenceWriter,execTool,fileDigest,requireThat,severity,subjectID} from "./scan-common.mjs";

const indexTypes = new Set(["application/vnd.oci.image.index.v1+json","application/vnd.docker.distribution.manifest.list.v2+json"]);
const manifestTypes = new Set(["application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"]);
const digestRE = /^sha256:[a-f0-9]{64}$/;

async function verifyBlob(layout, descriptor) {
  requireThat(digestRE.test(descriptor.digest) && Number.isSafeInteger(descriptor.size) && descriptor.size>=0,"invalid OCI descriptor");
  const source = path.join(layout,"blobs","sha256",descriptor.digest.slice(7));
  requireThat(statSync(source).size===descriptor.size && await fileDigest(source)===descriptor.digest.slice(7),
    "OCI digest or size mismatch");
  return source;
}
function readManifest(file) {
  requireThat(statSync(file).size <= 16<<20,"OCI manifest too large");
  const manifest = JSON.parse(readFileSync(file));
  requireThat(manifest.schemaVersion===2,"unsupported OCI manifest version");
  return manifest;
}
function platformName(platform) {
  return [platform?.os,platform?.architecture,platform?.variant].filter(Boolean).join("/");
}

// Copy only verified blobs to a single-manifest layout. Syft then scans the exact
// platform child of the rendered digest, even if the supplied layout also has tags.
export async function prepareOCI(image, layout, target, imageRoster = [image]) {
  requireThat(JSON.parse(readFileSync(path.join(layout,"oci-layout"))).imageLayoutVersion==="1.0.0","unsupported OCI layout");
  const root = readManifest(path.join(layout,"index.json"));
  const deployment = image.deploymentDigest??image.digest;
  const deployed = root.manifests.filter(d=>d.digest===deployment);
  requireThat(deployed.length>0,"rendered deployment digest missing from OCI layout");
  let child;
  if (deployment===image.digest) child = deployed[0];
  else {
    requireThat(indexTypes.has(deployed[0].mediaType),"multi-platform deployment requires a manifest index");
    const index = readManifest(await verifyBlob(layout,deployed[0]));
    for (const desc of index.manifests) {
      if (desc.platform?.os === "unknown" && desc.platform?.architecture === "unknown" &&
        desc.annotations?.["vnd.docker.reference.type"] === "attestation-manifest") continue;
      const covered = imageRoster.some(i => i.ref===image.ref && i.deploymentDigest===deployment &&
        i.platform===platformName(desc.platform) && i.digest===desc.digest);
      requireThat(covered,"rendered multi-platform index contains an unscanned child");
    }
    const choices = index.manifests.filter(d=>platformName(d.platform)===image.platform);
    requireThat(choices.length===1 && choices[0].digest===image.digest, "wrong platform child of deployment digest");
    child = choices[0];
  }
  requireThat(manifestTypes.has(child.mediaType),"expected platform image manifest");
  const manifest = readManifest(await verifyBlob(layout,child));
  requireThat(Array.isArray(manifest.layers) && manifest.layers.length<=500,"unsupported OCI image layers");
  const cfg = await verifyBlob(layout,manifest.config);
  requireThat(statSync(cfg).size<=16<<20,"OCI config too large");
  const imageConfig = JSON.parse(readFileSync(cfg));
  requireThat(platformName(imageConfig)===image.platform && (!child.platform || platformName(child.platform)===image.platform),
    "image platform mismatch");
  const dest = path.join(target,"blobs","sha256");
  mkdirSync(dest,{recursive:true,mode:0o700});
  for (const desc of [child,manifest.config,...manifest.layers]) {
    const source = await verifyBlob(layout,desc);
    const file = path.join(dest,desc.digest.slice(7));
    if (!existsSync(file)) {
      copyFileSync(source,file,constants.COPYFILE_EXCL|constants.COPYFILE_FICLONE);
      requireThat(await fileDigest(file)===desc.digest.slice(7),"staged image blob changed");
    }
  }
  writeFileSync(path.join(target,"oci-layout"),JSON.stringify({imageLayoutVersion:"1.0.0"}),{flag:"wx"});
  writeFileSync(path.join(target,"index.json"),JSON.stringify({schemaVersion:2,manifests:[child]}),{flag:"wx"});
}

export function grypeFindings(result) {
  requireThat(result.descriptor?.name==="grype" && Array.isArray(result.matches) &&
    (result.ignoredMatches===undefined || Array.isArray(result.ignoredMatches)), "invalid Grype report");
  // Suppression rules on a workstation must never bypass the release exception policy.
  return [...result.matches,...(result.ignoredMatches??[])].map(match=>{
    const v=match.vulnerability, a=match.artifact;
    requireThat(v && typeof v.id==="string" && a?.name && a.version && a.type, "unattributed image vulnerability");
    return {advisory:v.id,package:a.name,version:a.version,ecosystem:a.type,severity:severity(v.severity),
      fix:v.fix?.versions?.length ? v.fix.versions.join(", ") : null,withdrawn:false};
  });
}

// Reconcile separately scanned Go files with their actual runtime paths. A signed
// candidate naming both digests is insufficient if those files differ in the image.
export function verifyImageBinaries(syft, dockerfile, binaries, platform) {
  const finalStage = dockerfile.split(/^FROM\s+/m).at(-1);
  let cwd = "/";
  for (const line of finalStage.split("\n")) {
    if (line.startsWith("WORKDIR ")) cwd = path.posix.resolve(cwd,line.slice(8).trim());
    if (!line.startsWith("COPY ") || !line.includes("/out/")) continue;
    const items = line.trim().split(/\s+/).slice(1).filter(s=>!s.startsWith("--"));
    const dest = items.pop();
    requireThat(dest === "./" && items.length>0 && items.every(s=>/^\/out\/[a-z][a-z0-9-]+$/.test(s)),
      "unsupported product binary COPY instruction");
    for (const src of items) {
      const name = path.posix.basename(src);
      const binary = binaries.find(b=>b.name===name && b.platform===platform);
      const file = path.posix.join(cwd,name);
      const entries = syft.files?.filter(f=>f.location?.path===file) ?? [];
      requireThat(binary && entries.length===1 &&
        entries[0].digests?.some(d=>d.algorithm.toLowerCase()==="sha256" && d.value===binary.sha256),
        "product binary is missing or has a different digest inside the image");
    }
  }
}

export async function scanImage(img,config,env,work,outputDir,candidate,repoRoot) {
  const id = subjectID("image",img);
  const write = evidenceWriter(outputDir,id);
  const oci = path.join(work,"image");
  await prepareOCI(img,config.images[id],oci,candidate.images);
  const raw = execTool(config.tools.syft,["scan","oci-dir:"+oci,"-o","syft-json"],work,env);
  const report = JSON.parse(raw);
  requireThat(report.descriptor?.name==="syft" && Array.isArray(report.artifacts) && report.artifacts.length>0,
    "image package inventory missing");
  const reference = img.ref+"@"+(img.deploymentDigest??img.digest);
  for (const [role,ref] of Object.entries(candidate.productImages??{})) {
    if (ref === reference) {
      const dockerfile = readFileSync(path.join(repoRoot,"deploy","production",role+".Dockerfile"),"utf8");
      verifyImageBinaries(report,dockerfile,candidate.binaries,img.platform);
    }
  }
  const receipt = write("image-syft",raw);
  const sbomFile = path.join(outputDir,receipt.file);
  const spdx = execTool(config.tools.syft,["convert",sbomFile,"-o","spdx-json"],work,env);
  const doc = JSON.parse(spdx);
  requireThat(doc.spdxVersion?.startsWith("SPDX-2.") && doc.packages?.length>0,"image SPDX SBOM missing");
  const grypeEnv = {...env, GRYPE_DB_CACHE_DIR:config.sources.grype, GRYPE_DB_AUTO_UPDATE:"false",
    GRYPE_DB_VALIDATE_BY_HASH_ON_START:"true",GRYPE_CHECK_FOR_APP_UPDATE:"false"};
  const result = execTool(config.tools.grype,["sbom:"+sbomFile,"-o","json"],work,grypeEnv);
  const findings = grypeFindings(JSON.parse(result));
  return {id,findings,coverageGaps:[],artifacts:[receipt,write("image-spdx",spdx),write("image-grype",result)]};
}
