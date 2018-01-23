package service

import (
	"math/rand"

	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/cothority_template/ots/util"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

type Client struct {
	*onet.Client
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(ServiceName)}
}

func (c *Client) OTSDecrypt(r *onet.Roster, writeTxnSBF *skipchain.SkipBlockFix, readTxnSBF *skipchain.SkipBlockFix, inclusionProof *skipchain.BlockLink, acPubKeys []abstract.Point, privKey abstract.Scalar) ([]*util.DecryptedShare, onet.ClientError) {

	// network.RegisterMessage(&util.OTSDecryptReqData{})
	data := &util.OTSDecryptReqData{
		WriteTxnSBF:    writeTxnSBF,
		ReadTxnSBF:     readTxnSBF,
		InclusionProof: inclusionProof,
		ACPublicKeys:   acPubKeys,
	}
	msg, err := network.Marshal(data)
	if err != nil {
		return nil, onet.NewClientErrorCode(ErrorParse, err.Error())
	}

	sig, err := util.SignMessage(msg, privKey)
	if err != nil {
		return nil, onet.NewClientErrorCode(ErrorParse, err.Error())
	}

	decryptReq := &OTSDecryptReq{
		Roster:    r,
		Data:      data,
		Signature: &sig,
	}
	idx := rand.Int() % len(r.List)
	dst := r.List[idx]
	decryptReq.RootIndex = idx
	reply := &OTSDecryptResp{}
	err = c.SendProtobuf(dst, decryptReq, reply)
	if err != nil {
		return nil, onet.NewClientErrorCode(ErrorParse, err.Error())
	}

	if idx != 0 {
		for i := 0; i < len(r.List); i++ {
			tmp := reply.DecShares[i]
			if tmp.Index == 0 {
				reply.DecShares[i].Index = idx
			} else if tmp.Index <= idx {
				reply.DecShares[i].Index--
			}
		}
	}
	return reply.DecShares, nil
}
