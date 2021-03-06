package ocs

/*
The api.go defines the methods that can be called from the outside. Most
of the methods will take a roster so that the service knows which nodes
it should work with.

This part of the service runs on the client or the app.
*/

import (
	"errors"

	"github.com/dedis/student_17_ots/ots/util"
	"github.com/dedis/student_17_ots/protocol"
	"gopkg.in/dedis/cothority.v1/skipchain"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/network"
)

// Client is a structure to communicate with the OCS service
// service. It can handle connections to different nodes, and
// will re-use existing connections transparently. To force
// closing of all connections, use Client.Close()
type Client struct {
	*onet.Client
	sbc *skipchain.Client
}

// NewClient instantiates a new ocs.Client
func NewClient() *Client {
	return &Client{
		Client: onet.NewClient(ServiceName),
		sbc:    skipchain.NewClient(),
	}
}

// CreateSkipchain creates a new OCS-skipchain using the roster r. The OCS-service
// will create a new skipchain with an empty first genesis-block. You can create more
// than one skipchain at the same time.
//
// Input:
//  - r [*onet.Roster] - the roster of the nodes holding the new skipchain
//
// Returns:
//  - ocs [*SkipChainURL] - the identity of that new skipchain
//  - cerr [ClientError] - an eventual error if something went wrong, or nil
func (c *Client) CreateSkipchain(r *onet.Roster) (ocs *SkipChainURL,
	cerr onet.ClientError) {
	req := &CreateSkipchainsRequest{
		Roster: r,
	}
	reply := &CreateSkipchainsReply{}
	cerr = c.SendProtobuf(r.List[0], req, reply)
	if cerr != nil {
		return nil, cerr
	}
	ocs = NewSkipChainURL(reply.OCS)
	return
}

func (c *Client) WriteTxnRequest(ocs *SkipChainURL, G abstract.Point, scPubKeys []abstract.Point, encShares []*pvss.PubVerShare, encProofs []abstract.Point, hashEnc []byte, readList []abstract.Point, wrPrivKey abstract.Scalar) (sb *skipchain.SkipBlock, cerr onet.ClientError) {
	wtd := &util.WriteTxnData{
		G:            G,
		SCPublicKeys: scPubKeys,
		EncShares:    encShares,
		EncProofs:    encProofs,
		HashEnc:      hashEnc,
		ReaderPk:     readList[0],
	}
	wr := &WriteTxnRequest{
		WriteTxn: &DataOCSWriteTxn{
			Data: wtd,
		},
		Readers: &DataOCSReaders{
			ID:      []byte{},
			Readers: readList,
		},
		OCS: ocs.Genesis,
	}
	msg, err := network.Marshal(wtd)
	if err != nil {
		return nil, onet.NewClientErrorCode(ErrorParameter, err.Error())
	}

	// log.Info("Write transaction size is:", len(msg))
	sig, err := util.SignMessage(msg, wrPrivKey)
	if err != nil {
		return nil, onet.NewClientErrorCode(ErrorParameter, err.Error())
	}

	wr.WriteTxn.Signature = &sig
	reply := &WriteTxnReply{}
	cerr = c.SendProtobuf(ocs.Roster.List[0], wr, reply)
	sb = reply.SB
	return
}

// WriteRequest contacts the ocs-service and requests the addition of a new write-
// block with the given encData. The encData has already to be encrypted using the symmetric
// symKey. This method will encrypt the symKey using the public shared key of the
// ocs-service and only send this encrypted key over the network. The block will also
// contain the list of readers that are allowed to request the key.
//
// Input:
//  - ocs [*SkipChainURL] - the url of the skipchain to use
//  - encData [[]byte] - the data - already encrypted using symKey
//  - symKey [[]byte] - the symmetric key - it will be encrypted using the shared public key
//  - readList [[]abstract.point] - a list of public key that can request a re-encryption
//    of the symmetric encryption key
//
// Output:
//  - sb [*skipchain.SkipBlock] - the actual block written in the skipchain. The
//    Data-field of the block contains the actual write request.
//  - cerr [ClientError] - an eventual error if something went wrong, or nil
func (c *Client) WriteRequest(ocs *SkipChainURL, encData []byte, symKey []byte, readList []abstract.Point) (sb *skipchain.SkipBlock,
	cerr onet.ClientError) {
	if len(encData) > 1e7 {
		return nil, onet.NewClientErrorCode(ErrorParameter, "Cannot store data bigger than 10MB")
	}

	requestShared := &SharedPublicRequest{Genesis: ocs.Genesis}
	shared := &SharedPublicReply{}
	cerr = c.SendProtobuf(ocs.Roster.List[0], requestShared, shared)
	if cerr != nil {
		return
	}

	U, Cs := protocol.EncodeKey(network.Suite, shared.X, symKey)
	wr := &WriteRequest{
		Write: &DataOCSWrite{
			Data:    encData,
			U:       U,
			Cs:      Cs,
			Readers: []byte{},
		},
		Readers: &DataOCSReaders{
			ID:      []byte{},
			Readers: readList,
		},
		OCS: ocs.Genesis,
	}
	reply := &WriteReply{}
	cerr = c.SendProtobuf(ocs.Roster.List[0], wr, reply)
	sb = reply.SB
	return
}

func (c *Client) ReadTxnRequest(ocs *SkipChainURL, dataID skipchain.SkipBlockID, reader abstract.Scalar) (sb *skipchain.SkipBlock, cerr onet.ClientError) {
	return c.ReadRequest(ocs, dataID, reader)
}

// ReadRequest is used to request a re-encryption of the symmetric key of the
// given data. The ocs-skipchain will verify if the signature corresponds to
// one of the public keys given in the write-request, and only if this is valid,
// it will add the block to the skipchain.
//
// Input:
//  - ocs [*SkipChainURL] - the url of the skipchain to use
//  - data [skipchain.SkipBlockID] - the hash of the write-request where the
//    data is stored
//  - reader [abstract.Scalar] - the private key of the reader. It is used to
//    sign the request to authenticate to the skipchain.
//
// Output:
//  - sb [*skipchain.SkipBlock] - the read-request that has been added to the
//    skipchain if it accepted the signature.
//  - cerr [ClientError] - an eventual error if something went wrong, or nil
func (c *Client) ReadRequest(ocs *SkipChainURL, dataID skipchain.SkipBlockID,
	reader abstract.Scalar) (sb *skipchain.SkipBlock, cerr onet.ClientError) {
	sig, err := crypto.SignSchnorr(network.Suite, reader, dataID)
	if err != nil {
		return nil, onet.NewClientErrorCode(ErrorParameter, err.Error())
	}

	request := &ReadRequest{
		Read: &DataOCSRead{
			DataID:    dataID,
			Public:    network.Suite.Point().Mul(nil, reader),
			Signature: &sig,
		},
		OCS: ocs.Genesis,
	}
	reply := &ReadReply{}
	cerr = c.SendProtobuf(ocs.Roster.List[0], request, reply)
	if cerr != nil {
		return nil, cerr
	}
	return reply.SB, nil
}

// DecryptKeyRequest takes the id of a successful read-request and asks the cothority
// to re-encrypt the symmetric key under the reader's public key. The cothority
// does a distributed re-encryption, so that the actual symmetric key is never revealed
// to any of the nodes.
//
// Input:
//  - ocs [*SkipChainURL] - the url of the skipchain to use
//  - readID [skipchain.SkipBlockID] - the ID of the successful read-request
//  - reader [abstract.Scalar] - the private key of the reader. It will be used to
//    decrypt the symmetric key.
//
// Output:
//  - sym [[]byte] - the decrypted symmetric key
//  - cerr [ClientError] - an eventual error if something went wrong, or nil
func (c *Client) DecryptKeyRequest(ocs *SkipChainURL, readID skipchain.SkipBlockID, reader abstract.Scalar) (sym []byte,
	cerr onet.ClientError) {
	request := &DecryptKeyRequest{
		Read: readID,
	}
	reply := &DecryptKeyReply{}
	cerr = c.SendProtobuf(ocs.Roster.List[0], request, reply)
	if cerr != nil {
		return
	}

	var err error
	sym, err = protocol.DecodeKey(network.Suite, reply.X,
		reply.Cs, reply.XhatEnc, reader)
	if err != nil {
		return nil, onet.NewClientErrorCode(ErrorProtocol, "couldn't decode sym: "+err.Error())
	}
	return
}

func (c *Client) GetWriteTxn(ocs *SkipChainURL, dataID skipchain.SkipBlockID) (sb *skipchain.SkipBlock, writeTxn *DataOCSWriteTxn, cerr onet.ClientError) {
	cl := skipchain.NewClient()
	sb, cerr = cl.GetSingleBlock(ocs.Roster, dataID)
	if cerr != nil {
		return nil, nil, cerr
	}

	_, ocsDataI, err := network.Unmarshal(sb.Data)
	if err != nil {
		return nil, nil, onet.NewClientError(err)
	}

	ocsData, ok := ocsDataI.(*DataOCS)
	writeTxn = ocsData.WriteTxn
	if !ok || writeTxn == nil {
		return nil, nil, onet.NewClientError(errors.New("not correct type of data"))
	}
	return sb, writeTxn, nil
}

// GetData returns the encrypted data from a write-request given its id. It requests
// the data from the skipchain. To decode the data, the caller has to have a
// decrypted symmetric key, then he can decrypt the data with:
//
//   cipher := network.Suite.Cipher(key)
//   data, err := cipher.Open(nil, encData)
//
// Input:
//  - ocs [*SkipChainURL] - the url of the skipchain to use
//  - dataID [skipchain.SkipBlockID] - the hash of the skipblock where the data
//    is stored
//
// Output:
//  - cerr [ClientError] - an eventual error if something went wrong, or nil
func (c *Client) GetData(ocs *SkipChainURL, dataID skipchain.SkipBlockID) (encData []byte,
	cerr onet.ClientError) {
	cl := skipchain.NewClient()
	sb, cerr := cl.GetSingleBlock(ocs.Roster, dataID)
	if cerr != nil {
		return nil, cerr
	}
	_, ocsDataI, err := network.Unmarshal(sb.Data)
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	ocsData, ok := ocsDataI.(*DataOCS)
	if !ok || ocsData.Write == nil {
		return nil, onet.NewClientError(errors.New("not correct type of data"))
	}
	return ocsData.Write.Data, nil
}

// GetReadRequests searches the skipchain starting at 'start' for requests and returns all found
// requests. A maximum of 'count' requests are returned. If 'count' == 0, 'start'
// must point to a write-block, and all read-requests for that write-block will
// be returned.
//
// Input:
//  - ocs [*SkipChainURL] - the url of the skipchain to use
//
// Output:
//  - cerr [ClientError] - an eventual error if something went wrong, or nil
func (c *Client) GetReadRequests(ocs *SkipChainURL, start skipchain.SkipBlockID, count int) ([]*ReadDoc, onet.ClientError) {
	request := &GetReadRequests{start, count}
	reply := &GetReadRequestsReply{}
	cerr := c.SendProtobuf(ocs.Roster.List[0], request, reply)
	if cerr != nil {
		return nil, cerr
	}
	return reply.Documents, nil
}
