package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/cosmos/kms/gen/signerservice"
)

const (
	containerPort = "9090"
	keyID         = "e2e"
)

// TestSignerContainerE2E starts the container with a plaintext (no-TLS) gRPC SignerService,
// fetches the configured key, signs a digest, and verifies the returned recoverable
// signature recovers to that key.
func TestSignerContainerE2E(t *testing.T) {
	// LookPath alone is not enough: a docker CLI without a running daemon makes
	// testcontainers panic instead of erroring, so probe the daemon directly.
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker not available")
	}
	image := envOr("KMS_E2E_IMAGE", "kms:e2e")
	ctx := context.Background()

	// Generate a throwaway secp256k1 key kms config.
	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	wantPub := priv.PubKey().SerializeCompressed()

	kmsYAML := "grpc:\n" +
		"  listen: 0.0.0.0:" + containerPort + "\n" +
		"  keys:\n" +
		"    - id: " + keyID + "\n" +
		"      backend: file\n" +
		"      algorithm: secp256k1eth\n" +
		"      key_file: key.hex\n"

	// Copy config + key into the home dir the entrypoint reads.
	ctr, err := testcontainers.Run(ctx, image,
		testcontainers.WithExposedPorts(containerPort+"/tcp"),
		testcontainers.WithFiles(
			fileFromBytes([]byte(kmsYAML), "/home/kms/kms.yaml"),
			fileFromBytes([]byte(hex.EncodeToString(priv.Serialize())), "/home/kms/key.hex"),
		),
		testcontainers.WithWaitStrategy(wait.ForListeningPort(containerPort+"/tcp")),
	)
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)

	addr := mappedAddr(ctx, t, ctr)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := pb.NewSignerServiceClient(conn)

	keysResp, err := client.GetKeys(ctx, &pb.GetKeysRequest{})
	require.NoError(t, err)
	keys := keysResp.GetKeys()
	require.Len(t, keys, 1)
	require.Equal(t, keyID, keys[0].GetId())
	require.Equal(t, pb.SignatureScheme_ECDSA_SECP256K1ETH, keys[0].GetScheme())
	require.Equal(t, wantPub, keys[0].GetPubkey())

	// Sign a 32-byte digest and verify the recoverable signature.
	digest := sha256.Sum256([]byte("kms e2e"))
	signResp, err := client.Sign(ctx, &pb.SignRequest{
		KeyId:   keyID,
		Payload: &pb.Payload{Kind: &pb.Payload_Generic{Generic: digest[:]}},
	})
	require.NoError(t, err)

	sig := signResp.GetSignature()
	require.Len(t, sig, 65, "expected 65-byte r‖s‖v signature")
	v := sig[64]
	require.LessOrEqual(t, v, byte(1), "recovery id must be 0 or 1")

	// decred RecoverCompact takes <27+recid>‖R‖S; rebuild it from r‖s‖v.
	compact := append([]byte{27 + v}, sig[:64]...)
	recovered, _, err := ecdsa.RecoverCompact(compact, digest[:])
	require.NoError(t, err)
	require.Equal(t, wantPub, recovered.SerializeCompressed(), "signature must recover to the configured key")
}

func mappedAddr(ctx context.Context, t *testing.T, ctr testcontainers.Container) string {
	t.Helper()
	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	port, err := ctr.MappedPort(ctx, containerPort+"/tcp")
	require.NoError(t, err)
	return fmt.Sprintf("%s:%s", host, port.Port())
}

func fileFromBytes(content []byte, containerPath string) testcontainers.ContainerFile {
	return testcontainers.ContainerFile{
		Reader:            bytes.NewReader(content),
		ContainerFilePath: containerPath,
		FileMode:          0o644,
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
