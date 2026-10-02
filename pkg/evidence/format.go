// Package evidence implements DƏLİL evidence packages: ZIP files that let
// anyone verify a range of an audit stream offline, without database access
// and without trusting the server that produced them.
//
// Layout (format version 1):
//
//	manifest.json      what the package covers, and the SHA-256 of every other file
//	signature.json     Ed25519 signature over the manifest hash
//	chain.jsonl        integrity skeleton: every event header from the anchor to the
//	                   last selected event (no content)
//	events.jsonl       disclosed events: header and exact canonical content
//	checkpoints.json   signed checkpoints used as the anchor or inside the segment
//	public-keys.json   every key needed to verify the package
//	verification.json  the server's own verification at export time (informational)
//	README.txt         human-readable explanation
//
// The skeleton makes selective disclosure possible: the full chain from a
// signed anchor is verifiable, while only the selected events reveal content.
package evidence

import (
	"github.com/serxan22/delil/pkg/integrity"
)

// Format identifiers.
const (
	FormatName    = "delil-evidence-package"
	FormatVersion = 1
)

// File names inside a package.
const (
	FileManifest     = "manifest.json"
	FileSignature    = "signature.json"
	FileChain        = "chain.jsonl"
	FileEvents       = "events.jsonl"
	FileCheckpoints  = "checkpoints.json"
	FilePublicKeys   = "public-keys.json"
	FileVerification = "verification.json"
	FileReadme       = "README.txt"
)

// allowedFiles lists every entry a package may contain.
var allowedFiles = map[string]bool{
	FileManifest: true, FileSignature: true, FileChain: true, FileEvents: true, FileCheckpoints: true,
	FilePublicKeys: true, FileVerification: true, FileReadme: true,
}

// requiredFiles must be present in every package.
var requiredFiles = []string{FileManifest, FileSignature, FileChain, FileEvents, FileCheckpoints, FilePublicKeys}

// Manifest describes a package. Its canonical form is what signature.json signs.
type Manifest struct {
	Format        string      `json:"format"`
	FormatVersion int         `json:"formatVersion"`
	PackageID     string      `json:"packageId"`
	CreatedAt     string      `json:"createdAt"`
	Generator     Generator   `json:"generator"`
	Tenant        NamedID     `json:"tenant"`
	Project       NamedID     `json:"project"`
	Stream        string      `json:"stream"`
	Selection     Selection   `json:"selection"`
	Chain         ChainInfo   `json:"chain"`
	Files         []FileEntry `json:"files"`
	Notice        string      `json:"notice"`
}

// Generator identifies the software that wrote the package.
type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// NamedID is an identifier with a display name. Names are informational.
type NamedID struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Selection records what was requested and what was disclosed.
type Selection struct {
	FromSequence    int64             `json:"fromSequence"`
	ToSequence      int64             `json:"toSequence"`
	RecordedFrom    string            `json:"recordedFrom,omitempty"`
	RecordedTo      string            `json:"recordedTo,omitempty"`
	Filters         map[string]string `json:"filters"`
	DisclosedEvents int64             `json:"disclosedEvents"`
}

// ChainInfo describes the chain segment in chain.jsonl.
type ChainInfo struct {
	FirstSequence int64        `json:"firstSequence"`
	LastSequence  int64        `json:"lastSequence"`
	Events        int64        `json:"events"`
	Anchor        ChainAnchor  `json:"anchor"`
	StreamHead    HeadSnapshot `json:"streamHeadAtExport"`
}

// Anchor types.
const (
	AnchorGenesis    = "genesis"
	AnchorCheckpoint = "checkpoint"
)

// ChainAnchor is where the segment starts.
type ChainAnchor struct {
	Type         string `json:"type"`
	CheckpointID string `json:"checkpointId,omitempty"`
	Sequence     int64  `json:"sequence"`
	Hash         string `json:"hash"`
}

// HeadSnapshot is the stream head when the package was produced.
type HeadSnapshot struct {
	Sequence int64  `json:"sequence"`
	Hash     string `json:"hash"`
}

// FileEntry pins the content of one file.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// SignatureFile is the content of signature.json.
type SignatureFile struct {
	Algorithm    string              `json:"algorithm"`
	KeyID        string              `json:"keyId"`
	ManifestHash integrity.Hash      `json:"manifestHash"`
	Signature    integrity.Signature `json:"signature"`
}

// KeysFile is the content of public-keys.json (and of trusted-keys files).
type KeysFile struct {
	Keys []integrity.PublicKey `json:"keys"`
}

// CheckpointsFile is the content of checkpoints.json.
type CheckpointsFile struct {
	Checkpoints []integrity.Checkpoint `json:"checkpoints"`
}

// Notice is embedded in every manifest.
const Notice = "This package is cryptographically verifiable: it shows whether the included audit records were " +
	"altered, removed, inserted or reordered after they were committed. It does not by itself establish legal " +
	"admissibility, which depends on the applicable law and procedure."
