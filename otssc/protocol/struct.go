package protocol

import (
	"github.com/dedis/student_17_ots/ots/util"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
)

type AnnounceDecrypt struct {
	DecReqData *util.OTSDecryptReqData
	Signature  *crypto.SchnorrSig
	RootIndex  int
}

type StructAnnounceDecrypt struct {
	*onet.TreeNode
	AnnounceDecrypt
}

type DecryptReply struct {
	DecShare *util.DecryptedShare
}

type StructDecryptReply struct {
	*onet.TreeNode
	DecryptReply
}
