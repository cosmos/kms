package signerservice

import (
	"context"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/cosmos/kms/gen/signerservice"
	"github.com/cosmos/kms/signing"
)

// Server implements the SignerService gRPC service.
//
// The server performs no caller authentication or authorization: any client
// that can reach the listener may use any configured key. Access must be
// constrained entirely by transport/network controls (TLS, network policy).
type Server struct {
	pb.UnimplementedSignerServiceServer
	keys map[string]signing.Key
}

// NewServer builds a Server over the configured keys.
func NewServer(keys map[string]signing.Key) *Server {
	return &Server{keys: keys}
}

// lookupKey returns the configured key or a NotFound status error.
func (s *Server) lookupKey(keyID string) (signing.Key, error) {
	k, ok := s.keys[keyID]
	if !ok {
		return signing.Key{}, status.Errorf(codes.NotFound, "key %q not found", keyID)
	}
	return k, nil
}

func keyMessage(k signing.Key) *pb.Key {
	return &pb.Key{Id: k.ID, Pubkey: k.Signer.PubKey(), Scheme: k.Signer.Scheme()}
}

// Sign implements SignerService.Sign. The request carries no scheme; the
// payload is interpreted per the key's own scheme (see the SignatureScheme enum
// in the proto).
func (s *Server) Sign(_ context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	k, err := s.lookupKey(req.KeyId)
	if err != nil {
		return nil, err
	}
	payload := req.Payload.GetGeneric()
	// ECDSA_SECP256K1 signs a digest, not a message: enforce the 32-byte length
	// at the trust boundary so a malformed digest can't be signed.
	if k.Signer.Scheme() == pb.SignatureScheme_ECDSA_SECP256K1 && len(payload) != 32 {
		return nil, status.Error(codes.InvalidArgument, "ECDSA_SECP256K1 payload must be a 32-byte digest")
	}
	sig, err := k.Signer.Sign(context.TODO(), payload)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign: %v", err)
	}
	return &pb.SignResponse{Signature: sig}, nil
}

// GetKey implements SignerService.GetKey. pubkey is the canonical encoding for
// the key's scheme (ECDSA_SECP256K1 -> 33-byte compressed).
func (s *Server) GetKey(_ context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	k, err := s.lookupKey(req.Id)
	if err != nil {
		return nil, err
	}
	return &pb.GetKeyResponse{Key: keyMessage(k)}, nil
}

// GetKeys implements SignerService.GetKeys, returning every configured key.
func (s *Server) GetKeys(_ context.Context, _ *pb.GetKeysRequest) (*pb.GetKeysResponse, error) {
	ids := make([]string, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	resp := &pb.GetKeysResponse{}
	for _, id := range ids {
		resp.Keys = append(resp.Keys, keyMessage(s.keys[id]))
	}
	return resp, nil
}
