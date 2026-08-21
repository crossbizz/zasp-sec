package providercollection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type ResumeSeed = collection.ResumeSeed

var kubernetesResumeCursorPattern = regexp.MustCompile(`^kubernetes:(namespaces|serviceaccounts|roles|clusterroles|rolebindings|clusterrolebindings|deployments|statefulsets|daemonsets|jobs|cronjobs):([1-9][0-9]{0,5}):([A-Za-z0-9_-]+|start):([0-9a-f]{16}):([0-9a-f]{16})$`)

var oktaResumeCursorPattern = regexp.MustCompile(`^okta:(users|userroles|groups|groupmembers|grouproles|applications|appusers|appgroups|clientroles):([1-9][0-9]{0,5}):([A-Za-z0-9_-]+):([0-9a-f]{16})$`)

var githubResumeCursorPattern = regexp.MustCompile(`^github:(repositories|workflows|environments):([1-9][0-9]{0,5}):([A-Za-z0-9_-]+):([0-9a-f]{16})$`)

var (
	oktaResumeUserIDPattern   = regexp.MustCompile(`^00u[A-Za-z0-9]{16,64}$`)
	oktaResumeGroupIDPattern  = regexp.MustCompile(`^00g[A-Za-z0-9]{16,64}$`)
	oktaResumeAppIDPattern    = regexp.MustCompile(`^0oa[A-Za-z0-9]{16,64}$`)
	oktaResumeClientIDPattern = regexp.MustCompile(`^[A-Za-z0-9]{16,64}$`)
)

var kubernetesResumePhases = []string{"namespaces", "serviceaccounts", "roles", "clusterroles", "rolebindings", "clusterrolebindings", "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs"}

type oktaResumeCursorState struct {
	Phase       string `json:"p"`
	Lineage     int    `json:"l"`
	After       string `json:"a,omitempty"`
	ResumeAfter string `json:"r,omitempty"`
	PrincipalID string `json:"i,omitempty"`
	AppID       string `json:"x,omitempty"`
	ClientID    string `json:"c,omitempty"`
}

type githubResumeCursorState struct {
	Phase         string `json:"p"`
	Lineage       int    `json:"l"`
	ProviderPage  int    `json:"n,omitempty"`
	Total         int    `json:"t,omitempty"`
	PhasePage     int    `json:"x,omitempty"`
	PhaseTotal    int    `json:"z,omitempty"`
	OwnerID       int64  `json:"o,omitempty"`
	Owner         string `json:"a,omitempty"`
	AppID         int64  `json:"i,omitempty"`
	RepositoryID  int64  `json:"r,omitempty"`
	Repository    string `json:"q,omitempty"`
	DefaultBranch string `json:"b,omitempty"`
}

func (client *Client) WithResumeSeed(seed collection.ResumeSeed) (collection.ProviderClient, error) {
	if client == nil || !validResumeSeed(seed) {
		return nil, collection.ErrContract
	}
	clone := *client
	copyOfSeed := seed
	copyOfSeed.CheckpointDigest = bytes.Clone(seed.CheckpointDigest)
	copyOfSeed.ManifestChecksum = bytes.Clone(seed.ManifestChecksum)
	clone.resume = &copyOfSeed
	return &clone, nil
}

func validResumeSeed(seed collection.ResumeSeed) bool {
	return seed.CheckpointVersion >= 1 && seed.CheckpointVersion <= 10_000 && len(seed.CheckpointDigest) == sha256.Size && !bytes.Equal(seed.CheckpointDigest, make([]byte, sha256.Size)) &&
		seed.Cursor.Provider != "" && seed.Cursor.Version != "" && seed.Cursor.Value != "" && len(seed.ManifestReference) > len(seed.ManifestKey)+1 && strings.HasSuffix(seed.ManifestReference, "/"+seed.ManifestKey) &&
		len(seed.ManifestVersionID) >= 1 && len(seed.ManifestVersionID) <= 1024 && len(seed.ManifestChecksum) == sha256.Size && !bytes.Equal(seed.ManifestChecksum, make([]byte, sha256.Size)) &&
		seed.ManifestSizeBytes >= 1 && seed.ManifestSizeBytes <= maximumArtifactBytes && seed.ManifestMediaType == "application/json" && seed.ManifestSchema == manifestSchemaVersion &&
		versionPattern.MatchString(seed.ParserVersion) && versionPattern.MatchString(seed.ToolVersion)
}

type resumeState struct {
	objects               []collection.RawObject
	pages                 []Page
	entities              []json.RawMessage
	relationships         []json.RawMessage
	entityObjects         map[string]collection.RawObject
	entitySourceIDs       map[string]struct{}
	entityBodies          map[string]json.RawMessage
	relationshipIDs       map[string]struct{}
	relationshipSourceIDs map[string]struct{}
	budgetEntities        [][]json.RawMessage
	evidenceLengths       [][]int
	rawBytes              int64
}

func (client *Client) loadResumeSeed(ctx context.Context, request collection.Request) (resumeState, error) {
	seed := client.resume
	if seed == nil || !validResumeSeed(*seed) || seed.Cursor != request.Cursor || seed.ParserVersion != request.ParserVersion || seed.ToolVersion != request.ToolVersion {
		return resumeState{}, collection.ErrContract
	}
	manifestReference, err := evidenceReferenceFromKey(seed.ManifestKey)
	if err != nil {
		return resumeState{}, collection.ErrContract
	}
	locator := artifactstore.Locator{Scope: request.Scope, Reference: manifestReference, VersionID: seed.ManifestVersionID}
	manifestArtifact, err := client.artifacts.Get(ctx, locator)
	var expectedChecksum [sha256.Size]byte
	copy(expectedChecksum[:], seed.ManifestChecksum)
	if err != nil || !exactResumeArtifact(manifestArtifact, locator, seed.ManifestMediaType, seed.ManifestSizeBytes, expectedChecksum) {
		return resumeState{}, collection.ErrContract
	}
	objectReference, err := client.artifacts.ObjectReference(locator)
	if err != nil || objectReference != seed.ManifestReference {
		return resumeState{}, collection.ErrContract
	}
	var document manifestDocument
	if !decodeExactObject(manifestArtifact.Body, &document) || !validResumeManifest(document, request, *seed) {
		return resumeState{}, collection.ErrContract
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, manifestArtifact.Body) {
		return resumeState{}, collection.ErrContract
	}
	state := resumeState{
		objects: make([]collection.RawObject, 0, len(document.Objects)), pages: make([]Page, 0, len(document.Objects)), entities: make([]json.RawMessage, 0), relationships: make([]json.RawMessage, 0),
		entityObjects: make(map[string]collection.RawObject), entitySourceIDs: make(map[string]struct{}), entityBodies: make(map[string]json.RawMessage), relationshipIDs: make(map[string]struct{}), relationshipSourceIDs: make(map[string]struct{}), budgetEntities: make([][]json.RawMessage, 0, len(document.Objects)), evidenceLengths: make([][]int, 0, len(document.Objects)),
	}
	lastReference := ""
	cursorMatches := 0
	resumeCursors := make([]collection.Cursor, 0, len(document.Objects))
	for _, descriptor := range document.Objects {
		if descriptor.Reference <= lastReference {
			return resumeState{}, collection.ErrContract
		}
		lastReference = descriptor.Reference
		object, page, loadErr := client.loadResumePage(ctx, request, descriptor)
		if loadErr != nil || page.Complete {
			return resumeState{}, collection.ErrContract
		}
		if request.Provider == collection.ProviderKubernetes || request.Provider == collection.ProviderGitHub || request.Provider == collection.ProviderOkta {
			resumeCursors = append(resumeCursors, page.Cursor)
		}
		if page.Cursor == seed.Cursor {
			cursorMatches++
		}
		state.objects = append(state.objects, object)
		state.pages = append(state.pages, page)
		state.rawBytes += object.Size()
		pageEntities := make([]json.RawMessage, 0, len(page.Entities))
		for _, entity := range page.Entities {
			identity, source, ok := entityIdentity(entity)
			if !ok {
				return resumeState{}, collection.ErrContract
			}
			if _, exists := state.entityObjects[identity]; exists {
				if !coalescibleKubernetesPrincipal(request.Provider, entity) || !bytes.Equal(state.entityBodies[identity], entity) {
					return resumeState{}, collection.ErrContract
				}
				if _, sourceExists := state.entitySourceIDs[source]; !sourceExists {
					return resumeState{}, collection.ErrContract
				}
				continue
			}
			if _, exists := state.entitySourceIDs[source]; exists {
				return resumeState{}, collection.ErrContract
			}
			state.entityObjects[identity] = object
			state.entitySourceIDs[source] = struct{}{}
			state.entityBodies[identity] = bytes.Clone(entity)
			pageEntities = append(pageEntities, bytes.Clone(entity))
			state.entities = append(state.entities, bytes.Clone(entity))
		}
		lengths := make([]int, len(pageEntities))
		for index, entity := range pageEntities {
			identity, _, ok := entityIdentity(entity)
			if !ok {
				return resumeState{}, collection.ErrContract
			}
			item, itemErr := evidenceForEntity(request, identity, object)
			encoded, encodeErr := json.Marshal(item)
			if itemErr != nil || encodeErr != nil {
				return resumeState{}, collection.ErrContract
			}
			lengths[index] = len(encoded)
		}
		for _, relationship := range page.Relationships {
			identity, source, _, _, ok := relationshipIdentity(relationship)
			if !ok {
				return resumeState{}, collection.ErrContract
			}
			if _, exists := state.relationshipIDs[identity]; exists {
				return resumeState{}, collection.ErrContract
			}
			if _, exists := state.relationshipSourceIDs[source]; exists {
				return resumeState{}, collection.ErrContract
			}
			state.relationshipIDs[identity] = struct{}{}
			state.relationshipSourceIDs[source] = struct{}{}
			state.relationships = append(state.relationships, bytes.Clone(relationship))
		}
		state.budgetEntities = append(state.budgetEntities, pageEntities)
		state.evidenceLengths = append(state.evidenceLengths, lengths)
	}
	if len(state.objects) == 0 || cursorMatches != 1 || !validResumeCursorSequence(request.Provider, request.ExpectedSubject, resumeCursors) {
		return resumeState{}, collection.ErrContract
	}
	return state, nil
}

type sequencedResumeCursor struct {
	cursor  collection.Cursor
	lineage int
}

func validResumeCursorSequence(provider collection.Provider, subject collection.SubjectBinding, cursors []collection.Cursor) bool {
	if provider != collection.ProviderKubernetes && provider != collection.ProviderGitHub && provider != collection.ProviderOkta {
		return len(cursors) == 0
	}
	if len(cursors) == 0 {
		return false
	}
	sequence := make([]sequencedResumeCursor, 0, len(cursors))
	for _, cursor := range cursors {
		lineage, ok := resumeCursorLineage(provider, cursor)
		if !ok {
			return false
		}
		sequence = append(sequence, sequencedResumeCursor{cursor: cursor, lineage: lineage})
	}
	sort.Slice(sequence, func(left, right int) bool { return sequence[left].lineage < sequence[right].lineage })
	priorCursor := collection.Cursor{}
	priorKubernetesPhase := ""
	priorGitHubState := githubResumeCursorState{}
	priorOktaState := oktaResumeCursorState{}
	for index, item := range sequence {
		expectedLineage := index + 2
		if item.lineage != expectedLineage {
			return false
		}
		if provider == collection.ProviderKubernetes {
			phase, valid := validKubernetesResumeCursor(item.cursor, subject, priorCursor, priorKubernetesPhase, expectedLineage)
			if !valid {
				return false
			}
			priorCursor = item.cursor
			priorKubernetesPhase = phase
			continue
		}
		if provider == collection.ProviderGitHub {
			state, valid := validGitHubResumeCursor(item.cursor, subject, priorGitHubState, expectedLineage)
			if !valid {
				return false
			}
			priorGitHubState = state
			continue
		}
		state, valid := validOktaResumeCursor(item.cursor, subject, priorOktaState, expectedLineage)
		if !valid {
			return false
		}
		priorOktaState = state
	}
	return true
}

func resumeCursorLineage(provider collection.Provider, cursor collection.Cursor) (int, bool) {
	pattern := kubernetesResumeCursorPattern
	if provider == collection.ProviderGitHub {
		pattern = githubResumeCursorPattern
	} else if provider == collection.ProviderOkta {
		pattern = oktaResumeCursorPattern
	}
	match := pattern.FindStringSubmatch(cursor.Value)
	lineage, err := strconv.Atoi(matchValue(match, 2))
	return lineage, err == nil && lineage >= 2 && lineage <= 1_000_000
}

func validGitHubResumeCursor(cursor collection.Cursor, subject collection.SubjectBinding, prior githubResumeCursorState, expectedLineage int) (githubResumeCursorState, bool) {
	if cursor.Provider != collection.ProviderGitHub || cursor.Version != "cursor_v1" || subject.Kind != "github_installation" || subject.ID == "" {
		return githubResumeCursorState{}, false
	}
	match := githubResumeCursorPattern.FindStringSubmatch(cursor.Value)
	lineage, lineageErr := strconv.Atoi(matchValue(match, 2))
	payload, decodeErr := base64.RawURLEncoding.DecodeString(matchValue(match, 3))
	var state githubResumeCursorState
	if lineageErr != nil || decodeErr != nil || lineage != expectedLineage || len(payload) < 2 || len(payload) > 1350 || !decodeExactObject(payload, &state) || state.Phase != matchValue(match, 1) || state.Lineage != lineage || !validGitHubResumeState(state) || matchValue(match, 4) != CursorBinding(collection.ProviderGitHub, subject, state.Phase, state.Lineage, matchValue(match, 3)) {
		return githubResumeCursorState{}, false
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(canonical, payload) || !validGitHubResumeTransition(prior, state) {
		return githubResumeCursorState{}, false
	}
	return state, true
}

func validGitHubResumeState(state githubResumeCursorState) bool {
	if state.Lineage < 2 || state.Lineage > 1_000_000 || state.ProviderPage < 1 || state.ProviderPage > 1_000_000 || state.Total < 0 || state.Total > 10_000 || state.OwnerID < 1 || state.OwnerID > 1<<53 || state.AppID < 1 || state.AppID > 1<<53 || !validResumeText(state.Owner, 100) {
		return false
	}
	if state.Phase == "repositories" {
		return state.RepositoryID == 0 && state.Repository == "" && state.DefaultBranch == "" && state.PhasePage == 0 && state.PhaseTotal == 0
	}
	return (state.Phase == "workflows" || state.Phase == "environments") && state.Total >= 1 && state.ProviderPage >= 2 && state.ProviderPage <= state.Total+1 && state.PhasePage >= 1 && state.PhasePage <= 10_000 && state.PhaseTotal >= 0 && state.PhaseTotal <= 10_000 && state.RepositoryID >= 1 && state.RepositoryID <= 1<<53 && githubResumeNamePattern.MatchString(state.Repository) && validResumeText(state.DefaultBranch, 255)
}

var githubResumeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

func validResumeText(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validGitHubResumeTransition(prior, current githubResumeCursorState) bool {
	if prior.Phase == "" {
		return current.Phase == "repositories" && current.ProviderPage == 1 && current.Total == 0
	}
	if !sameGitHubResumeInstallation(prior, current) {
		return false
	}
	switch prior.Phase {
	case "repositories":
		return current.Phase == "workflows" && current.ProviderPage == prior.ProviderPage+1 && current.Total >= current.ProviderPage-1 && current.PhasePage == 1 && current.PhaseTotal == 0
	case "workflows":
		if current.Phase == "workflows" {
			return sameGitHubResumeRepository(prior, current) && current.PhasePage == prior.PhasePage+1 && current.PhaseTotal >= current.PhasePage
		}
		return current.Phase == "environments" && sameGitHubResumeRepository(prior, current) && current.PhasePage == 1 && current.PhaseTotal == 0
	case "environments":
		if current.Phase == "environments" {
			return sameGitHubResumeRepository(prior, current) && current.PhasePage == prior.PhasePage+1 && current.PhaseTotal >= current.PhasePage
		}
		return current.Phase == "repositories" && current.ProviderPage == prior.ProviderPage && current.Total == prior.Total
	default:
		return false
	}
}

func sameGitHubResumeInstallation(left, right githubResumeCursorState) bool {
	return left.OwnerID == right.OwnerID && left.Owner == right.Owner && left.AppID == right.AppID
}

func sameGitHubResumeRepository(left, right githubResumeCursorState) bool {
	return left.ProviderPage == right.ProviderPage && left.Total == right.Total && left.RepositoryID == right.RepositoryID && left.Repository == right.Repository && left.DefaultBranch == right.DefaultBranch
}

func validOktaResumeCursor(cursor collection.Cursor, subject collection.SubjectBinding, prior oktaResumeCursorState, expectedLineage int) (oktaResumeCursorState, bool) {
	if cursor.Provider != collection.ProviderOkta || cursor.Version != "cursor_v1" || subject.Kind != "okta_tenant" || subject.ID == "" {
		return oktaResumeCursorState{}, false
	}
	match := oktaResumeCursorPattern.FindStringSubmatch(cursor.Value)
	lineage, lineageErr := strconv.Atoi(matchValue(match, 2))
	payload, decodeErr := base64.RawURLEncoding.DecodeString(matchValue(match, 3))
	var state oktaResumeCursorState
	if lineageErr != nil || decodeErr != nil || lineage != expectedLineage || len(payload) < 2 || len(payload) > 1350 || !decodeExactObject(payload, &state) || state.Phase != matchValue(match, 1) || state.Lineage != lineage || !validOktaResumeState(state) || matchValue(match, 4) != CursorBinding(collection.ProviderOkta, subject, state.Phase, state.Lineage, matchValue(match, 3)) {
		return oktaResumeCursorState{}, false
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(canonical, payload) || !validOktaResumeTransition(prior, state) {
		return oktaResumeCursorState{}, false
	}
	return state, true
}

func validOktaResumeState(state oktaResumeCursorState) bool {
	if state.Lineage < 2 || state.Lineage > 1_000_000 || !validOktaResumeAfter(state.After) || !validOktaResumeAfter(state.ResumeAfter) {
		return false
	}
	switch state.Phase {
	case "users", "groups", "applications":
		return state.PrincipalID == "" && state.AppID == "" && state.ClientID == "" && state.ResumeAfter == ""
	case "userroles":
		return oktaResumeUserIDPattern.MatchString(state.PrincipalID) && state.AppID == "" && state.ClientID == "" && state.After == ""
	case "groupmembers":
		return oktaResumeGroupIDPattern.MatchString(state.PrincipalID) && state.AppID == "" && state.ClientID == ""
	case "grouproles":
		return oktaResumeGroupIDPattern.MatchString(state.PrincipalID) && state.AppID == "" && state.ClientID == "" && state.After == ""
	case "appusers", "appgroups":
		return state.PrincipalID == "" && oktaResumeAppIDPattern.MatchString(state.AppID) && (state.ClientID == "" || oktaResumeClientIDPattern.MatchString(state.ClientID))
	case "clientroles":
		return state.PrincipalID == "" && oktaResumeAppIDPattern.MatchString(state.AppID) && oktaResumeClientIDPattern.MatchString(state.ClientID) && state.After == ""
	default:
		return false
	}
}

func validOktaResumeAfter(value string) bool {
	if len(value) > 1536 || strings.ContainsAny(value, "&=?#") {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validOktaResumeTransition(prior, current oktaResumeCursorState) bool {
	if prior.Phase == "" {
		return current.Phase == "userroles" || current.Phase == "groups" && current.After == ""
	}
	switch prior.Phase {
	case "users":
		return current.Phase == "userroles" || current.Phase == "groups" && current.After == ""
	case "userroles":
		if prior.ResumeAfter != "" {
			return current.Phase == "users" && current.After == prior.ResumeAfter
		}
		return current.Phase == "groups" && current.After == ""
	case "groups":
		return current.Phase == "groupmembers" || current.Phase == "applications"
	case "groupmembers":
		if current.Phase == "groupmembers" {
			return current.PrincipalID == prior.PrincipalID && current.ResumeAfter == prior.ResumeAfter && current.After != "" && current.After != prior.After
		}
		return current.Phase == "grouproles" && current.PrincipalID == prior.PrincipalID && current.ResumeAfter == prior.ResumeAfter
	case "grouproles":
		if prior.ResumeAfter != "" {
			return current.Phase == "groups" && current.After == prior.ResumeAfter
		}
		return current.Phase == "applications" && current.After == ""
	case "applications":
		return current.Phase == "appusers"
	case "appusers":
		if current.Phase == "appusers" {
			return sameOktaResumeApplication(prior, current) && current.After != "" && current.After != prior.After
		}
		return current.Phase == "appgroups" && sameOktaResumeApplication(prior, current)
	case "appgroups":
		if current.Phase == "appgroups" {
			return sameOktaResumeApplication(prior, current) && current.After != "" && current.After != prior.After
		}
		if prior.ClientID != "" {
			return current.Phase == "clientroles" && sameOktaResumeApplication(prior, current)
		}
		return oktaResumeReturnsToApplications(prior, current)
	case "clientroles":
		return oktaResumeReturnsToApplications(prior, current)
	default:
		return false
	}
}

func sameOktaResumeApplication(left, right oktaResumeCursorState) bool {
	return left.AppID == right.AppID && left.ClientID == right.ClientID && left.ResumeAfter == right.ResumeAfter
}

func oktaResumeReturnsToApplications(prior, current oktaResumeCursorState) bool {
	return current.Phase == "applications" && prior.ResumeAfter != "" && current.After == prior.ResumeAfter
}

func validKubernetesResumeCursor(cursor collection.Cursor, subject collection.SubjectBinding, prior collection.Cursor, priorPhase string, expectedLineage int) (string, bool) {
	if cursor.Provider != collection.ProviderKubernetes || cursor.Version != "cursor_v1" {
		return "", false
	}
	match := kubernetesResumeCursorPattern.FindStringSubmatch(cursor.Value)
	phase, continuation := matchValue(match, 1), matchValue(match, 3)
	lineage, err := strconv.Atoi(matchValue(match, 2))
	if err != nil || lineage != expectedLineage {
		return "", false
	}
	if priorPhase == "" {
		if (phase == "namespaces" && continuation == "start") || (phase != "namespaces" && phase != "serviceaccounts") || (phase == "serviceaccounts" && continuation != "start") {
			return "", false
		}
	} else if phase == priorPhase {
		if continuation == "start" {
			return "", false
		}
	} else if nextKubernetesResumePhase(priorPhase) != phase || continuation != "start" {
		return "", false
	}
	priorValue := prior.Value
	if prior == (collection.Cursor{}) || priorValue == "initial" {
		priorValue = "initial"
	}
	digest := sha256.Sum256([]byte("kubernetes-cursor-chain-v1\x1f" + priorValue))
	priorBinding := fmt.Sprintf("%x", digest[:8])
	return phase, matchValue(match, 4) == priorBinding && matchValue(match, 5) == CursorBinding(collection.ProviderKubernetes, subject, phase, expectedLineage, continuation+":"+priorBinding)
}

func nextKubernetesResumePhase(phase string) string {
	for index := 0; index+1 < len(kubernetesResumePhases); index++ {
		if kubernetesResumePhases[index] == phase {
			return kubernetesResumePhases[index+1]
		}
	}
	return ""
}

func matchValue(matches []string, index int) string {
	if index < 0 || index >= len(matches) {
		return ""
	}
	return matches[index]
}

func (client *Client) loadResumePage(ctx context.Context, request collection.Request, descriptor manifestDescriptor) (collection.RawObject, Page, error) {
	reference, err := evidenceReferenceFromKey(descriptor.Key)
	checksumBytes, checksumErr := hex.DecodeString(descriptor.ChecksumHex)
	if err != nil || checksumErr != nil || len(checksumBytes) != sha256.Size || descriptor.Reference != reference.String() || descriptor.SchemaVersion != rawSchemaVersion || descriptor.MediaType != "application/json" {
		return collection.RawObject{}, Page{}, collection.ErrContract
	}
	locator := artifactstore.Locator{Scope: request.Scope, Reference: reference, VersionID: descriptor.VersionID}
	artifact, err := client.artifacts.Get(ctx, locator)
	var checksum [sha256.Size]byte
	copy(checksum[:], checksumBytes)
	if err != nil || !exactResumeArtifact(artifact, locator, descriptor.MediaType, descriptor.SizeBytes, checksum) {
		return collection.RawObject{}, Page{}, collection.ErrContract
	}
	objectReference, err := client.artifacts.ObjectReference(locator)
	if err != nil || objectReference != descriptor.ObjectReference {
		return collection.RawObject{}, Page{}, collection.ErrContract
	}
	var document redactedPageDocument
	if !decodeExactObject(artifact.Body, &document) || document.Version != redactedPageVersion || document.Provider != request.Provider || document.Subject != (manifestSubject{Kind: request.ExpectedSubject.Kind, ID: request.ExpectedSubject.ID}) {
		return collection.RawObject{}, Page{}, collection.ErrContract
	}
	page := Page{Subject: request.ExpectedSubject, Cursor: collection.Cursor{Provider: document.Cursor.Provider, Version: document.Cursor.Version, Value: document.Cursor.Value}, Complete: document.Complete, Entities: cloneRawMessages(document.Entities), Relationships: cloneRawMessages(document.Relationships), Raw: bytes.Clone(artifact.Body)}
	canonical, canonicalErr := canonicalPageBody(request.Provider, page)
	if canonicalErr != nil || !bytes.Equal(canonical, artifact.Body) {
		return collection.RawObject{}, Page{}, collection.ErrContract
	}
	object, err := collection.NewRawObject(request.Scope, reference, descriptor.Key, descriptor.VersionID, descriptor.ObjectReference, checksum, descriptor.SizeBytes, descriptor.MediaType, descriptor.SchemaVersion, request.ParserVersion, request.ToolVersion)
	return object, page, err
}

func validResumeManifest(document manifestDocument, request collection.Request, seed collection.ResumeSeed) bool {
	digest, err := hex.DecodeString(document.RequestDigest)
	return err == nil && len(digest) == sha256.Size && !bytes.Equal(digest, make([]byte, sha256.Size)) && document.Version == manifestSchemaVersion && document.Provider == request.Provider &&
		document.Subject == (manifestSubject{Kind: request.ExpectedSubject.Kind, ID: request.ExpectedSubject.ID}) && document.IntegrationID == request.IntegrationID.String() && document.ConnectionID == request.ConnectionID.String() && document.JobID == request.JobID.String() &&
		document.Attempt >= 1 && document.Attempt <= request.Attempt && document.CollectorVersion == request.CollectorVersion && document.CursorProvider == seed.Cursor.Provider && document.CursorVersion == seed.Cursor.Version && document.CursorValue == seed.Cursor.Value &&
		document.ParserVersion == seed.ParserVersion && document.ToolVersion == seed.ToolVersion && len(document.Objects) >= 1 && len(document.Objects) <= request.Bounds.MaxPages
}

func exactResumeArtifact(artifact artifactstore.Artifact, locator artifactstore.Locator, mediaType string, size int64, checksum [sha256.Size]byte) bool {
	return artifact.Locator == locator && artifact.MediaType == mediaType && artifact.Size == size && artifact.Size == int64(len(artifact.Body)) && artifact.SHA256 == checksum && sha256.Sum256(artifact.Body) == checksum
}

func evidenceReferenceFromKey(key string) (domain.EvidenceRef, error) {
	last := strings.LastIndexByte(key, '/')
	if last < 0 || last == len(key)-1 {
		return domain.EvidenceRef{}, collection.ErrContract
	}
	id, err := domain.ParseProductID(key[last+1:])
	if err != nil {
		return domain.EvidenceRef{}, collection.ErrContract
	}
	return domain.NewEvidenceRef(id)
}
