package main

import (
	"bytes"
	"flag"
	"os"

	ots "github.com/dedis/cothority_template/ots"
	util "github.com/dedis/cothority_template/ots/util"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1/log"
)

func main() {

	numTrusteePtr := flag.Int("t", 0, "size of the SC cothority")
	filePtr := flag.String("g", "", "group.toml file for trustees")
	pkFilePtr := flag.String("p", "", "pk.txt file")
	dbgPtr := flag.Int("d", 0, "debug level")
	flag.Parse()
	log.SetDebugVisible(*dbgPtr)

	el, err := util.ReadRoster(*filePtr)
	if err != nil {
		log.Errorf("Couldn't read group.toml file: %v", err)
		os.Exit(1)
	}

	gr := util.GetGroup(*filePtr)
	scurl, err := ots.CreateSkipchain(gr.Roster)
	if err != nil {
		log.Errorf("Could not create skipchain: %v", err)
		os.Exit(1)
	}

	scPubKeys, err := ots.GetPubKeys(pkFilePtr)
	if err != nil {
		log.Errorf("Couldn't read pk file: %v", err)
		os.Exit(1)
	}

	dataPVSS := util.DataPVSS{
		Suite:        ed25519.NewAES128SHA256Ed25519(false),
		SCPublicKeys: scPubKeys,
		NumTrustee:   *numTrusteePtr,
	}
	// Writer's pk/sk pair
	wrPrivKey := dataPVSS.Suite.Scalar().Pick(random.Stream)
	wrPubKey := dataPVSS.Suite.Point().Mul(nil, wrPrivKey)
	// Reader's pk/sk pair
	privKey := dataPVSS.Suite.Scalar().Pick(random.Stream)
	pubKey := dataPVSS.Suite.Point().Mul(nil, privKey)

	err = ots.SetupPVSS(&dataPVSS, pubKey)
	if err != nil {
		log.Errorf("Could not setup PVSS: %v", err)
		os.Exit(1)
	}

	mesgSize := 1024 * 1024
	mesg := make([]byte, mesgSize)
	for i := 0; i < mesgSize; i++ {
		mesg[i] = 'w'
	}
	encMesg, hashEnc, err := ots.EncryptMessage(&dataPVSS, mesg)
	if err != nil {
		log.Errorf("Could not encrypt message: %v", err)
		os.Exit(1)
	}

	// Creating write transaction
	writeSB, err := ots.CreateWriteTxn(scurl, &dataPVSS, hashEnc, pubKey, wrPrivKey)
	if err != nil {
		log.Errorf("Could not create write transaction: %v", err)
		os.Exit(1)
	}

	// Bob gets it from Alice
	writeID := writeSB.Hash
	// Get write transaction from skipchain
	writeSB, writeTxnData, sig, err := ots.GetWriteTxnSB(scurl, writeID)
	if err != nil {
		log.Errorf("Could not retrieve write transaction block: %v", err)
		os.Exit(1)
	}

	sigVerErr := ots.VerifyTxnSignature(writeTxnData, sig, wrPubKey)
	if sigVerErr != nil {
		log.Errorf("Signature verification failed on the write transaction: %v", sigVerErr)
		os.Exit(1)
	}

	log.Info("Signature verified on the retrieved write transaction")
	validHash := ots.VerifyEncMesg(writeTxnData, encMesg)
	if validHash == 0 {
		log.Info("Valid hash for encrypted message")
	} else {
		log.Errorf("Invalid hash for encrypted message")
		os.Exit(1)
	}

	// Creating read transaction
	readSB, err := ots.CreateReadTxn(scurl, writeID, privKey)
	if err != nil {
		log.Errorf("Could not create read transaction: %v", err)
		os.Exit(1)
	}

	updWriteSB, err := ots.GetUpdatedWriteTxnSB(scurl, writeID)
	if err != nil {
		log.Errorf("Could not retrieve updated write txn SB: %v", err)
		os.Exit(1)
	}

	acPubKeys := readSB.Roster.Publics()
	// Bob obtains the SC public keys from T_W
	scPubKeys = writeTxnData.SCPublicKeys
	decShares, err := ots.GetDecryptedShares(scurl, el, updWriteSB, readSB.SkipBlockFix, acPubKeys, scPubKeys, privKey, readSB.Index)
	if err != nil {
		log.Errorf("Could not get the decrypted shares: %v", err)
		os.Exit(1)
	}

	var validKeys []abstract.Point
	var validEncShares []*pvss.PubVerShare
	var validDecShares []*pvss.PubVerShare
	sz := len(decShares)
	for i := 0; i < sz; i++ {
		validKeys = append(validKeys, writeTxnData.SCPublicKeys[i])
		validEncShares = append(validEncShares, writeTxnData.EncShares[i])
		validDecShares = append(validDecShares, decShares[i])
	}

	// Normally Bob doesn't have dataPVSS but we are
	// using it only for PVSS parameters for simplicity
	recSecret, err := pvss.RecoverSecret(dataPVSS.Suite, writeTxnData.G, validKeys, validEncShares, validDecShares, dataPVSS.Threshold, dataPVSS.NumTrustee)
	if err != nil {
		log.Errorf("Could not recover secret: %v", err)
		os.Exit(1)
	}

	log.Info("Recovered secret")
	recMesg, err := ots.DecryptMessage(recSecret, encMesg, writeTxnData)
	if err != nil {
		log.Errorf("Could not decrypt message: %v", err)
		os.Exit(1)
	}
	log.Info("Recovered message?:", (bytes.Compare(recMesg, mesg) == 0))
	// log.Info("Recovered message is:", string(recMesg))

	////////////////////////////////////////////////////

	//Creating fake write transaction
	// fakePrivKey := dataPVSS.Suite.Scalar().Pick(random.Stream)
	// fakePubKey := dataPVSS.Suite.Point().Mul(nil, fakePrivKey)
	// fakeWriteSB, err := ots.CreateWriteTxn(scurl, &dataPVSS, hashEnc, fakePubKey, wrPrivKey)
	// if err != nil {
	// 	log.Errorf("Could not create write txn: %v", err)
	// 	os.Exit(1)
	// }
	//
	// fakeWriteID := fakeWriteSB.Hash
	// readSB, err = ots.CreateReadTxn(scurl, fakeWriteID, fakePrivKey)
	// if err != nil {
	// 	log.Errorf("Could not create read txn: %v", err)
	// 	os.Exit(1)
	// }
	//
	// updFakeWriteSB, err := ots.GetUpdatedWriteTxnSB(scurl, fakeWriteID)
	// if err != nil {
	// 	log.Errorf("Could not retrieve updated write txn SB: %v", err)
	// 	os.Exit(1)
	// }
	//
	// acPubKeys = readSB.Roster.Publics()
	// // Bob obtains the SC public keys from T_W
	// scPubKeys = writeTxnData.SCPublicKeys
	// // ots.TestSkipchain(scurl, dataPVSS)
	// // diffSk := dataPVSS.Suite.Scalar().Pick(random.Stream)
	//
	// decShares, err = ots.GetDecryptedShares(scurl, el, updFakeWriteSB, readSB.SkipBlockFix, acPubKeys, scPubKeys, fakePrivKey, readSB.Index)
	//
	// if err != nil {
	// 	log.Errorf("Could not get the decrypted shares: %v", err)
	// 	os.Exit(1)
	// }
	//
	// var fakevalidKeys []abstract.Point
	// var fakevalidEncShares []*pvss.PubVerShare
	// var fakevalidDecShares []*pvss.PubVerShare
	//
	// sz = len(decShares)
	// for i := 0; i < sz; i++ {
	// 	fakevalidKeys = append(fakevalidKeys, writeTxnData.SCPublicKeys[i])
	// 	fakevalidEncShares = append(fakevalidEncShares, writeTxnData.EncShares[i])
	// 	fakevalidDecShares = append(fakevalidDecShares, decShares[i])
	// }
	//
	// fmt.Println("Number of valid fake dec share:", len(fakevalidDecShares))
	// fmt.Println("Number of valid fake enc share:", len(fakevalidEncShares))
	// // Normally Bob doesn't have dataPVSS but we are
	// // using it only for PVSS parameters for simplicity
	// recSecret, err = pvss.RecoverSecret(dataPVSS.Suite, writeTxnData.G, fakevalidKeys, fakevalidEncShares, fakevalidDecShares, dataPVSS.Threshold, dataPVSS.NumTrustee)
	//
	// if err != nil {
	// 	log.Errorf("Could not recover secret: %v", err)
	// 	os.Exit(1)
	// }
	//
	// recMesg = ots.DecryptMessage(recSecret, encMesg, writeTxnData)
	// log.Info("Recovered message is:", recMesg)
}
