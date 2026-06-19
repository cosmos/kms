package signerservice

import (
	"context"
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/cosmos/kms/gen/signerservice"
	"github.com/cosmos/kms/signing"
	"github.com/cosmos/kms/signing/file"
)

// Secp256k1Signer must satisfy the signing.Signer contract the server signs through.
var _ signing.Signer = (*file.Secp256k1Signer)(nil)

func newKey(t *testing.T) *file.Secp256k1Signer {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "k.hex")
	require.NoError(t, os.WriteFile(p, []byte("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"), 0o600))
	s, err := file.LoadSecp256k1FromFile(p)
	require.NoError(t, err)
	return s
}

func dialTestServer(t *testing.T, srv *Server) pb.SignerServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	pb.RegisterSignerServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewSignerServiceClient(conn)
}

func TestSignRecoverableRecovers(t *testing.T) {
	k := newKey(t)
	srv := NewServer(map[string]signing.Key{"attestor-1": {ID: "attestor-1", Signer: k}})
	client := dialTestServer(t, srv)

	// ECDSA_SECP256K1 signs a 32-byte digest; the client hashes the message.
	digest := sha256.Sum256([]byte("attest this"))
	resp, err := client.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "attestor-1",
		Payload: &pb.Payload{Kind: &pb.Payload_Generic{Generic: digest[:]}},
	})
	require.NoError(t, err)
	require.Len(t, resp.Signature, 65) // r‖s‖v

	// Recover the pubkey over the digest and compare to the key.
	r, s, v := resp.Signature[:32], resp.Signature[32:64], resp.Signature[64]
	compact := make([]byte, 65)
	compact[0] = 27 + v
	copy(compact[1:33], r)
	copy(compact[33:65], s)
	recovered, _, err := ecdsa.RecoverCompact(compact, digest[:])
	require.NoError(t, err)
	require.Equal(t, k.PubKeyUncompressed(), recovered.SerializeUncompressed())
}

func TestSignUnknownKey(t *testing.T) {
	srv := NewServer(map[string]signing.Key{})
	client := dialTestServer(t, srv)
	_, err := client.Sign(context.Background(), &pb.SignRequest{KeyId: "nope"})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestGetKey(t *testing.T) {
	k := newKey(t)
	srv := NewServer(map[string]signing.Key{"attestor-1": {ID: "attestor-1", Signer: k}})
	client := dialTestServer(t, srv)
	resp, err := client.GetKey(context.Background(), &pb.GetKeyRequest{Id: "attestor-1"})
	require.NoError(t, err)
	require.Equal(t, "attestor-1", resp.Key.Id)
	require.Equal(t, k.PubKey(), resp.Key.Pubkey)
	require.Equal(t, pb.SignatureScheme_ECDSA_SECP256K1, resp.Key.Scheme)
}

func TestSignBadDigestLength(t *testing.T) {
	k := newKey(t)
	srv := NewServer(map[string]signing.Key{"attestor-1": {ID: "attestor-1", Signer: k}})
	client := dialTestServer(t, srv)
	_, err := client.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "attestor-1",
		Payload: &pb.Payload{Kind: &pb.Payload_Generic{Generic: []byte("not-a-32-byte-digest")}},
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetKeysReturnsAllSorted(t *testing.T) {
	k1, k2 := newKey(t), newKey(t)
	srv := NewServer(map[string]signing.Key{
		"attestor-2": {ID: "attestor-2", Signer: k2},
		"attestor-1": {ID: "attestor-1", Signer: k1},
	})
	client := dialTestServer(t, srv)
	resp, err := client.GetKeys(context.Background(), &pb.GetKeysRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Keys, 2)
	require.Equal(t, "attestor-1", resp.Keys[0].Id)
	require.Equal(t, "attestor-2", resp.Keys[1].Id)
}
