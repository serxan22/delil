package evidence

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/jcs"
)

// Builder writes a package entry by entry. Entries are written in order;
// Finish adds the manifest and signature and closes the archive.
type Builder struct {
	zw      *zip.Writer
	files   []FileEntry
	written map[string]bool
	modTime time.Time
	cur     *entryWriter
}

type entryWriter struct {
	name string
	w    io.Writer
	h    hash.Hash
	n    int64
}

func (e *entryWriter) Write(p []byte) (int, error) {
	n, err := e.w.Write(p)
	e.h.Write(p[:n])
	e.n += int64(n)
	return n, err
}

// NewBuilder starts a package. modTime is stored as every entry's
// modification time so that packages are byte-for-byte reproducible.
func NewBuilder(w io.Writer, modTime time.Time) *Builder {
	return &Builder{zw: zip.NewWriter(w), written: map[string]bool{}, modTime: modTime.UTC()}
}

func (b *Builder) open(name string) (*entryWriter, error) {
	if b.cur != nil {
		b.close()
	}
	if !allowedFiles[name] || name == FileManifest || name == FileSignature {
		return nil, fmt.Errorf("evidence: %q is not a writable package entry", name)
	}
	if b.written[name] {
		return nil, fmt.Errorf("evidence: %q written twice", name)
	}
	w, err := b.zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: b.modTime})
	if err != nil {
		return nil, err
	}
	b.written[name] = true
	b.cur = &entryWriter{name: name, w: w, h: sha256.New()}
	return b.cur, nil
}

func (b *Builder) close() {
	if b.cur == nil {
		return
	}
	b.files = append(b.files, FileEntry{Path: b.cur.name, SHA256: hex.EncodeToString(b.cur.h.Sum(nil)), Size: b.cur.n})
	b.cur = nil
}

// JSONLWriter appends one JSON document per line.
type JSONLWriter struct {
	w     io.Writer
	count int64
}

// Write encodes v on its own line. HTML escaping is disabled so canonical
// content is stored byte for byte.
func (j *JSONLWriter) Write(v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := j.w.Write(buf.Bytes())
	if err == nil {
		j.count++
	}
	return err
}

// Count returns how many lines were written.
func (j *JSONLWriter) Count() int64 { return j.count }

// WriteJSONL writes a JSON Lines entry through fn.
func (b *Builder) WriteJSONL(name string, fn func(*JSONLWriter) error) (int64, error) {
	w, err := b.open(name)
	if err != nil {
		return 0, err
	}
	jw := &JSONLWriter{w: w}
	if err := fn(jw); err != nil {
		return 0, err
	}
	b.close()
	return jw.count, nil
}

// WriteJSON writes v as an indented JSON document.
func (b *Builder) WriteJSON(name string, v any) error {
	data, err := marshalIndent(v)
	if err != nil {
		return err
	}
	return b.WriteFile(name, data)
}

// WriteFile writes raw bytes.
func (b *Builder) WriteFile(name string, data []byte) error {
	w, err := b.open(name)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	b.close()
	return nil
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ManifestHash computes the hash that signature.json signs:
// SHA-256("delil:v1:manifest" || 0x00 || JCS(manifest)).
func ManifestHash(m *Manifest) (integrity.Hash, error) {
	canonical, err := jcs.Marshal(m)
	if err != nil {
		return integrity.Hash{}, err
	}
	return integrity.TaggedHash(integrity.TagManifest, canonical), nil
}

// Finish completes the manifest with the file list, signs it and closes the
// archive. It returns the manifest hash.
func (b *Builder) Finish(ctx context.Context, m Manifest, signer integrity.Signer) (integrity.Hash, error) {
	b.close()
	for _, name := range requiredFiles {
		if name != FileManifest && name != FileSignature && !b.written[name] {
			return integrity.Hash{}, fmt.Errorf("evidence: required file %s was not written", name)
		}
	}
	m.Format = FormatName
	m.FormatVersion = FormatVersion
	m.Files = append([]FileEntry(nil), b.files...)
	if m.Notice == "" {
		m.Notice = Notice
	}
	if m.Selection.Filters == nil {
		m.Selection.Filters = map[string]string{}
	}
	mh, err := ManifestHash(&m)
	if err != nil {
		return integrity.Hash{}, err
	}
	sig, err := signer.Sign(ctx, integrity.SigningMessage(integrity.TagManifestSignature, mh))
	if err != nil {
		return integrity.Hash{}, err
	}
	if !integrity.VerifySignature(signer.PublicKey(), integrity.TagManifestSignature, mh, sig) {
		return integrity.Hash{}, errors.New("evidence: signer produced an invalid manifest signature")
	}
	manifestBytes, err := marshalIndent(m)
	if err != nil {
		return integrity.Hash{}, err
	}
	sigBytes, err := marshalIndent(SignatureFile{Algorithm: integrity.AlgorithmEd25519, KeyID: signer.KeyID(),
		ManifestHash: mh, Signature: sig})
	if err != nil {
		return integrity.Hash{}, err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{FileManifest, manifestBytes}, {FileSignature, sigBytes}} {
		w, err := b.zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: b.modTime})
		if err != nil {
			return integrity.Hash{}, err
		}
		if _, err := w.Write(f.data); err != nil {
			return integrity.Hash{}, err
		}
	}
	return mh, b.zw.Close()
}
