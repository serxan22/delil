package evidence

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/jcs"
	"github.com/serxan22/delil/pkg/verify"
)

// Limits protect the verifier against hostile archives (zip bombs).
type Limits struct {
	MaxEntries       int
	MaxEntryBytes    int64
	MaxTotalBytes    int64
	MaxMetadataBytes int64
	MaxLineBytes     int
	MaxRatio         int64
}

// DefaultLimits suit packages of up to a few million events.
var DefaultLimits = Limits{
	MaxEntries:       16,
	MaxEntryBytes:    4 << 30,
	MaxTotalBytes:    8 << 30,
	MaxMetadataBytes: 64 << 20,
	MaxLineBytes:     8 << 20,
	MaxRatio:         200,
}

// Options configure offline verification.
type Options struct {
	// TrustedKeys, when set, is the only source of trust. Otherwise the keys
	// shipped in the package are used and the report says so: they prove
	// that the package is internally consistent, not who produced it.
	TrustedKeys *integrity.KeySet
	Limits      Limits
	Verifier    *verify.VerifierInfo
}

// PackageInfo summarizes the package for reports.
type PackageInfo struct {
	PackageID           string    `json:"packageId"`
	CreatedAt           string    `json:"createdAt"`
	Generator           Generator `json:"generator"`
	Tenant              NamedID   `json:"tenant"`
	Project             NamedID   `json:"project"`
	Selection           Selection `json:"selection"`
	ChainAnchor         string    `json:"chainAnchor"`
	ManifestHash        string    `json:"manifestHash,omitempty"`
	SignedBy            string    `json:"signedBy,omitempty"`
	KeysTrusted         bool      `json:"keysTrusted"`
	ServerReportedValid *bool     `json:"serverReportedValid,omitempty"`
	FilesVerified       int       `json:"filesVerified"`
}

// Result is the outcome of verifying a package.
type Result struct {
	*verify.Report
	Package PackageInfo `json:"package"`
}

// VerifyFile verifies the package at path.
func VerifyFile(path string, opts Options) (*Result, error) {
	f, err := os.Open(path) //nolint:gosec // the user chooses which package to verify
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return Verify(f, info.Size(), opts)
}

// Verify verifies a package. Structural problems that make further checks
// meaningless return a failed report, not an error; errors are reserved for
// I/O failures.
func Verify(r io.ReaderAt, size int64, opts Options) (*Result, error) {
	if opts.Limits == (Limits{}) {
		opts.Limits = DefaultLimits
	}
	pv := &packageVerifier{opts: opts, files: map[string]*zip.File{}}
	return pv.run(r, size)
}

type packageVerifier struct {
	opts     Options
	files    map[string]*zip.File
	early    []verify.Failure
	manifest Manifest
	info     PackageInfo
}

func (pv *packageVerifier) fail(code verify.Code, format string, args ...any) {
	pv.early = append(pv.early, verify.Failure{Code: code, Message: fmt.Sprintf(format, args...)})
}

// failedReport returns a report containing only package-level failures.
func (pv *packageVerifier) failedReport() *Result {
	v := verify.NewStreamVerifier(verify.StreamOptions{Scope: verify.ScopeEvidencePackage, Verifier: pv.opts.Verifier,
		TenantID: pv.manifest.Tenant.ID, ProjectID: pv.manifest.Project.ID, Stream: pv.manifest.Stream})
	for _, f := range pv.early {
		v.AddFailure(f)
	}
	rep := v.Finish()
	return &Result{Report: rep, Package: pv.info}
}

func (pv *packageVerifier) run(r io.ReaderAt, size int64) (*Result, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		pv.fail(verify.CodePackageMalformed, "not a readable ZIP archive: %v", err)
		return pv.failedReport(), nil
	}
	if !pv.checkEntries(zr) {
		return pv.failedReport(), nil
	}

	manifestRaw, err := pv.readSmall(FileManifest)
	if err != nil {
		return nil, err
	}
	sigRaw, err := pv.readSmall(FileSignature)
	if err != nil {
		return nil, err
	}
	if !pv.parseManifest(manifestRaw) {
		return pv.failedReport(), nil
	}
	if !pv.checkDigests() {
		return pv.failedReport(), nil
	}

	var keysFile KeysFile
	if err := pv.readJSON(FilePublicKeys, &keysFile); err != nil {
		pv.fail(verify.CodePackageMalformed, "public-keys.json: %v", err)
		return pv.failedReport(), nil
	}
	keySet, rejected := integrity.NewKeySetLenient(keysFile.Keys...)
	keySource := "embedded in the package (compare fingerprints with an independently obtained copy)"
	if pv.opts.TrustedKeys != nil {
		keySet, rejected = pv.opts.TrustedKeys, nil
		keySource = "pinned trusted keys"
		pv.info.KeysTrusted = true
	}

	pv.checkManifestSignature(manifestRaw, sigRaw, keySet)

	var cpFile CheckpointsFile
	if err := pv.readJSON(FileCheckpoints, &cpFile); err != nil {
		pv.fail(verify.CodePackageMalformed, "checkpoints.json: %v", err)
		return pv.failedReport(), nil
	}
	anchor, ok := pv.anchor(cpFile.Checkpoints)
	if !ok {
		return pv.failedReport(), nil
	}

	if f, ok := pv.files[FileVerification]; ok {
		var server struct {
			Valid *bool `json:"valid"`
		}
		if data, err := readLimited(f, pv.opts.Limits.MaxMetadataBytes); err == nil && json.Unmarshal(data, &server) == nil {
			pv.info.ServerReportedValid = server.Valid
		}
	}

	m := &pv.manifest
	sv := verify.NewStreamVerifier(verify.StreamOptions{
		TenantID:     m.Tenant.ID,
		ProjectID:    m.Project.ID,
		Stream:       m.Stream,
		Keys:         keySet,
		KeySource:    keySource,
		RejectedKeys: rejected,
		Anchor:       &anchor,
		Checkpoints:  cpFile.Checkpoints,
		Scope:        verify.ScopeEvidencePackage,
		Verifier:     pv.opts.Verifier,
	})
	for _, f := range pv.early {
		sv.AddFailure(f)
	}
	if err := pv.verifyChain(sv); err != nil {
		return nil, err
	}
	rep := sv.Finish()
	return &Result{Report: rep, Package: pv.info}, nil
}

// checkEntries rejects anything but a flat set of known, regular files.
func (pv *packageVerifier) checkEntries(zr *zip.Reader) bool {
	lim := pv.opts.Limits
	if len(zr.File) > lim.MaxEntries {
		pv.fail(verify.CodePackageMalformed, "archive has %d entries; at most %d are allowed", len(zr.File), lim.MaxEntries)
		return false
	}
	var total uint64
	ok := true
	for _, f := range zr.File {
		name := f.Name
		switch {
		case strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") || strings.HasPrefix(name, "."):
			pv.fail(verify.CodePackageMalformed, "unsafe entry name %q (paths and traversal are not allowed)", name)
			ok = false
			continue
		case !allowedFiles[name]:
			pv.fail(verify.CodePackageMalformed, "unexpected entry %q", name)
			ok = false
			continue
		case pv.files[name] != nil:
			pv.fail(verify.CodePackageMalformed, "duplicate entry %q (ambiguous archive)", name)
			ok = false
			continue
		case !f.Mode().IsRegular():
			pv.fail(verify.CodePackageMalformed, "entry %q is not a regular file", name)
			ok = false
			continue
		case f.UncompressedSize64 > uint64(lim.MaxEntryBytes): //nolint:gosec // limits are positive
			pv.fail(verify.CodePackageMalformed, "entry %q is too large", name)
			ok = false
			continue
		case f.CompressedSize64 > 0 && f.UncompressedSize64/f.CompressedSize64 > uint64(lim.MaxRatio) && f.UncompressedSize64 > 1<<20: //nolint:gosec // limits are positive
			pv.fail(verify.CodePackageMalformed, "entry %q has a suspicious compression ratio", name)
			ok = false
			continue
		}
		total += f.UncompressedSize64
		pv.files[name] = f
	}
	if total > uint64(lim.MaxTotalBytes) { //nolint:gosec // limits are positive
		pv.fail(verify.CodePackageMalformed, "archive expands to more than %d bytes", lim.MaxTotalBytes)
		ok = false
	}
	for _, name := range requiredFiles {
		if pv.files[name] == nil {
			pv.fail(verify.CodePackageMalformed, "required file %s is missing", name)
			ok = false
		}
	}
	return ok
}

func readLimited(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", f.Name, limit)
	}
	return data, nil
}

func (pv *packageVerifier) readSmall(name string) ([]byte, error) {
	return readLimited(pv.files[name], pv.opts.Limits.MaxMetadataBytes)
}

func (pv *packageVerifier) readJSON(name string, v any) error {
	data, err := pv.readSmall(name)
	if err != nil {
		return err
	}
	if _, err := jcs.Parse(data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (pv *packageVerifier) parseManifest(raw []byte) bool {
	if _, err := jcs.Parse(raw); err != nil {
		pv.fail(verify.CodePackageMalformed, "manifest.json is not valid JSON: %v", err)
		return false
	}
	if err := json.Unmarshal(raw, &pv.manifest); err != nil {
		pv.fail(verify.CodePackageMalformed, "manifest.json does not match the format: %v", err)
		return false
	}
	m := &pv.manifest
	if m.Format != FormatName || m.FormatVersion != FormatVersion {
		pv.fail(verify.CodePackageMalformed, "unsupported package format %q version %d", m.Format, m.FormatVersion)
		return false
	}
	pv.info = PackageInfo{PackageID: m.PackageID, CreatedAt: m.CreatedAt, Generator: m.Generator, Tenant: m.Tenant,
		Project: m.Project, Selection: m.Selection, ChainAnchor: m.Chain.Anchor.Type}
	return true
}

// checkDigests compares every file with its manifest entry. The manifest is
// signed, so this extends the signature to every file.
func (pv *packageVerifier) checkDigests() bool {
	listed := map[string]bool{}
	ok := true
	for _, fe := range pv.manifest.Files {
		if listed[fe.Path] || fe.Path == FileManifest || fe.Path == FileSignature {
			pv.fail(verify.CodePackageMalformed, "manifest lists %q more than once or lists itself", fe.Path)
			ok = false
			continue
		}
		listed[fe.Path] = true
		f := pv.files[fe.Path]
		if f == nil {
			pv.fail(verify.CodePackageDigestMismatch, "manifest lists %s, which is missing from the archive", fe.Path)
			ok = false
			continue
		}
		sum, n, err := digest(f, pv.opts.Limits.MaxEntryBytes)
		if err != nil {
			pv.fail(verify.CodePackageMalformed, "cannot read %s: %v", fe.Path, err)
			ok = false
			continue
		}
		if sum != fe.SHA256 || n != fe.Size {
			pv.early = append(pv.early, verify.Failure{Code: verify.CodePackageDigestMismatch,
				Message:  fmt.Sprintf("%s does not match the manifest; the file was modified after export", fe.Path),
				Expected: fe.SHA256, Found: sum})
			ok = false
			continue
		}
		pv.info.FilesVerified++
	}
	for name := range pv.files {
		if name != FileManifest && name != FileSignature && !listed[name] {
			pv.fail(verify.CodePackageDigestMismatch, "%s is not listed in the manifest (added after export)", name)
			ok = false
		}
	}
	return ok
}

func digest(f *zip.File, limit int64) (string, int64, error) {
	rc, err := f.Open()
	if err != nil {
		return "", 0, err
	}
	defer rc.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(rc, limit+1))
	if err != nil {
		return "", 0, err
	}
	if n > limit {
		return "", 0, errors.New("entry exceeds the size limit")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func (pv *packageVerifier) checkManifestSignature(manifestRaw, sigRaw []byte, keys *integrity.KeySet) {
	var sf SignatureFile
	if _, err := jcs.Parse(sigRaw); err != nil {
		pv.fail(verify.CodeManifestSignatureInvalid, "signature.json is not valid JSON: %v", err)
		return
	}
	if err := json.Unmarshal(sigRaw, &sf); err != nil {
		pv.fail(verify.CodeManifestSignatureInvalid, "signature.json does not match the format: %v", err)
		return
	}
	canonical, err := jcs.Canonicalize(manifestRaw)
	if err != nil {
		pv.fail(verify.CodeManifestSignatureInvalid, "manifest cannot be canonicalized: %v", err)
		return
	}
	mh := integrity.TaggedHash(integrity.TagManifest, canonical)
	pv.info.ManifestHash = mh.String()
	pv.info.SignedBy = sf.KeyID
	if !mh.Equal(sf.ManifestHash) {
		pv.early = append(pv.early, verify.Failure{Code: verify.CodeManifestSignatureInvalid,
			Message: "the manifest was modified after it was signed", Expected: sf.ManifestHash.String(), Found: mh.String()})
		return
	}
	key, ok := keys.Get(sf.KeyID)
	if !ok {
		pv.fail(verify.CodeManifestSignatureInvalid, "the manifest is signed by key %s, which is not trusted", sf.KeyID)
		return
	}
	if sf.Algorithm != integrity.AlgorithmEd25519 ||
		!integrity.VerifySignature(key.Ed25519(), integrity.TagManifestSignature, mh, sf.Signature) {
		pv.fail(verify.CodeManifestSignatureInvalid, "the manifest signature does not verify under key %s", sf.KeyID)
	}
}

// anchor resolves where chain.jsonl starts.
func (pv *packageVerifier) anchor(cps []integrity.Checkpoint) (verify.Anchor, bool) {
	a := pv.manifest.Chain.Anchor
	switch a.Type {
	case AnchorGenesis:
		if pv.manifest.Chain.FirstSequence != 1 {
			pv.fail(verify.CodePackageUnanchored, "the chain is anchored at genesis but starts at sequence %d", pv.manifest.Chain.FirstSequence)
			return verify.Anchor{}, false
		}
		return verify.GenesisAnchor(), true
	case AnchorCheckpoint:
		for _, cp := range cps {
			if cp.CheckpointID == a.CheckpointID {
				if cp.Sequence != pv.manifest.Chain.FirstSequence-1 {
					pv.fail(verify.CodePackageUnanchored, "anchor checkpoint %s is at sequence %d, but the chain starts at %d",
						cp.CheckpointID, cp.Sequence, pv.manifest.Chain.FirstSequence)
					return verify.Anchor{}, false
				}
				// The checkpoint's signature is verified with the other
				// checkpoints; an invalid one fails the report.
				return verify.Anchor{Sequence: cp.Sequence, Hash: cp.HeadHash,
					Description: fmt.Sprintf("checkpoint %s (sequence %d)", cp.CheckpointID, cp.Sequence)}, true
			}
		}
		pv.fail(verify.CodePackageUnanchored, "anchor checkpoint %s is not included in checkpoints.json", a.CheckpointID)
		return verify.Anchor{}, false
	default:
		pv.fail(verify.CodePackageUnanchored, "unknown anchor type %q", a.Type)
		return verify.Anchor{}, false
	}
}

type lineReader struct {
	sc   *bufio.Scanner
	rc   io.Closer
	line int
}

func (pv *packageVerifier) openLines(name string) (*lineReader, error) {
	rc, err := pv.files[name].Open()
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(io.LimitReader(rc, pv.opts.Limits.MaxEntryBytes))
	sc.Buffer(make([]byte, 64*1024), pv.opts.Limits.MaxLineBytes)
	return &lineReader{sc: sc, rc: rc}, nil
}

// next returns the next record, or nil at the end.
func (l *lineReader) next() (*integrity.Record, error) {
	for l.sc.Scan() {
		l.line++
		line := bytes.TrimSpace(l.sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if _, err := jcs.Parse(line); err != nil {
			return nil, fmt.Errorf("line %d: %w", l.line, err)
		}
		var rec integrity.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", l.line, err)
		}
		return &rec, nil
	}
	return nil, l.sc.Err()
}

func sameHeader(a, b *integrity.Record) bool {
	return a.Header == b.Header && a.EventHash == b.EventHash && bytes.Equal(a.Signature, b.Signature)
}

// verifyChain merges the skeleton with the disclosed events (both sorted by
// sequence) and streams them through the engine.
func (pv *packageVerifier) verifyChain(sv *verify.StreamVerifier) error {
	chain, err := pv.openLines(FileChain)
	if err != nil {
		return err
	}
	defer chain.rc.Close()
	events, err := pv.openLines(FileEvents)
	if err != nil {
		return err
	}
	defer events.rc.Close()

	m := &pv.manifest
	var (
		batch          []verify.Item
		chainCount     int64
		disclosedCount int64
		firstSeq       int64
		lastSeq        int64
		prevDisclosed  int64
	)
	nextDisclosed, err := events.next()
	if err != nil {
		pv.fail(verify.CodePackageMalformed, "events.jsonl %v", err)
		nextDisclosed = nil
	}
	for {
		rec, err := chain.next()
		if err != nil {
			sv.AddFailure(verify.Failure{Code: verify.CodePackageMalformed, Message: "chain.jsonl " + err.Error()})
			break
		}
		if rec == nil {
			break
		}
		if rec.HasContent() {
			sv.AddFailure(verify.Failure{Code: verify.CodePackageMalformed, Sequence: rec.Sequence, EventID: rec.EventID,
				Message: "chain.jsonl must not contain event content"})
			rec.Content = nil
		}
		chainCount++
		if chainCount == 1 {
			firstSeq = rec.Sequence
		}
		lastSeq = rec.Sequence
		item := verify.Item{Record: *rec}
		for nextDisclosed != nil && nextDisclosed.Sequence < rec.Sequence {
			sv.AddFailure(verify.Failure{Code: verify.CodeDisclosureMismatch, Sequence: nextDisclosed.Sequence,
				EventID: nextDisclosed.EventID, Message: "a disclosed event is not part of the chain skeleton"})
			if nextDisclosed, err = events.next(); err != nil {
				sv.AddFailure(verify.Failure{Code: verify.CodePackageMalformed, Message: "events.jsonl " + err.Error()})
				nextDisclosed = nil
			}
		}
		if nextDisclosed != nil && nextDisclosed.Sequence == rec.Sequence {
			disclosedCount++
			switch {
			case !sameHeader(nextDisclosed, rec):
				sv.AddFailure(verify.Failure{Code: verify.CodeDisclosureMismatch, Sequence: rec.Sequence, EventID: rec.EventID,
					Message: "the disclosed event's header differs from the chain skeleton"})
			case !nextDisclosed.HasContent():
				sv.AddFailure(verify.Failure{Code: verify.CodeDisclosureMismatch, Sequence: rec.Sequence, EventID: rec.EventID,
					Message: "a disclosed event has no content"})
			case nextDisclosed.Sequence < m.Selection.FromSequence || nextDisclosed.Sequence > m.Selection.ToSequence:
				sv.AddFailure(verify.Failure{Code: verify.CodeSelectionMismatch, Sequence: rec.Sequence, EventID: rec.EventID,
					Message: "a disclosed event lies outside the selected range"})
			default:
				item.Record = *nextDisclosed
			}
			prevDisclosed = rec.Sequence
			if nextDisclosed, err = events.next(); err != nil {
				sv.AddFailure(verify.Failure{Code: verify.CodePackageMalformed, Message: "events.jsonl " + err.Error()})
				nextDisclosed = nil
			}
			if nextDisclosed != nil && nextDisclosed.Sequence <= prevDisclosed {
				sv.AddFailure(verify.Failure{Code: verify.CodePackageMalformed, Sequence: nextDisclosed.Sequence,
					Message: "events.jsonl is not in ascending sequence order"})
			}
		}
		batch = append(batch, item)
		if len(batch) == 1000 {
			sv.Add(batch)
			batch = nil
		}
	}
	if len(batch) > 0 {
		sv.Add(batch)
	}
	for nextDisclosed != nil {
		sv.AddFailure(verify.Failure{Code: verify.CodeDisclosureMismatch, Sequence: nextDisclosed.Sequence,
			EventID: nextDisclosed.EventID, Message: "a disclosed event is beyond the end of the chain skeleton"})
		if nextDisclosed, err = events.next(); err != nil {
			nextDisclosed = nil
		}
	}

	c := m.Chain
	if chainCount != c.Events || (chainCount > 0 && (firstSeq != c.FirstSequence || lastSeq != c.LastSequence)) {
		sv.AddFailure(verify.Failure{Code: verify.CodeSelectionMismatch,
			Message:  "chain.jsonl does not match the chain described in the manifest",
			Expected: fmt.Sprintf("%d events, sequences %d..%d", c.Events, c.FirstSequence, c.LastSequence),
			Found:    fmt.Sprintf("%d events, sequences %d..%d", chainCount, firstSeq, lastSeq)})
	}
	if disclosedCount != m.Selection.DisclosedEvents {
		sv.AddFailure(verify.Failure{Code: verify.CodeSelectionMismatch,
			Message:  "events.jsonl does not contain the number of events stated in the manifest",
			Expected: fmt.Sprint(m.Selection.DisclosedEvents), Found: fmt.Sprint(disclosedCount)})
	}
	if len(m.Selection.Filters) == 0 && m.Selection.DisclosedEvents != m.Selection.ToSequence-m.Selection.FromSequence+1 {
		sv.AddFailure(verify.Failure{Code: verify.CodeSelectionMismatch,
			Message:  "without filters every event of the selected range must be disclosed",
			Expected: fmt.Sprint(m.Selection.ToSequence - m.Selection.FromSequence + 1),
			Found:    fmt.Sprint(m.Selection.DisclosedEvents)})
	}
	if lastSeq != m.Selection.ToSequence && chainCount > 0 {
		sv.AddFailure(verify.Failure{Code: verify.CodeSelectionMismatch,
			Message: fmt.Sprintf("the chain ends at %d but the selection ends at %d", lastSeq, m.Selection.ToSequence)})
	}
	return nil
}
