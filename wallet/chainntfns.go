// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"math/big"
	"time"

	"gogs.doschain.org/doschain/dosd/blockchain"
	"gogs.doschain.org/doschain/dosd/blockchain/stake"
	"gogs.doschain.org/doschain/dosd/chaincfg/chainhash"
	"gogs.doschain.org/doschain/dosd/dosutil"
	"gogs.doschain.org/doschain/dosd/gcs"
	"gogs.doschain.org/doschain/dosd/txscript"
	"gogs.doschain.org/doschain/dosd/wire"
	"gogs.doschain.org/doschain/doswallet/errors"
	"gogs.doschain.org/doschain/doswallet/wallet/udb"
	"gogs.doschain.org/doschain/doswallet/wallet/walletdb"
)

var (
	rootLastNonce = []byte("nonce")
)

func (w *Wallet) extendMainChain(op errors.Op, dbtx walletdb.ReadWriteTx, header *wire.BlockHeader, f *gcs.Filter, transactions []*wire.MsgTx) ([]wire.OutPoint, error) {
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	blockHash := header.BlockHash()

	// Propagate the error unless this block is already included in the main
	// chain.
	err := w.TxStore.ExtendMainChain(txmgrNs, header, f)
	if err != nil && !errors.Is(errors.Exist, err) {
		return nil, errors.E(op, err)
	}

	// Notify interested clients of the connected block.
	w.NtfnServer.notifyAttachedBlock(dbtx, header, &blockHash)

	blockMeta, err := w.TxStore.GetBlockMetaForHash(txmgrNs, &blockHash)
	if err != nil {
		return nil, errors.E(op, err)
	}

	var watch []wire.OutPoint
	for _, tx := range transactions {
		rec, err := udb.NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			return nil, errors.E(op, err)
		}
		ops, err := w.processTransactionRecord(dbtx, rec, header, &blockMeta)
		if err != nil {
			return nil, errors.E(op, err)
		}
		watch = append(watch, ops...)
	}

	return watch, nil
}

// ChainSwitch updates the wallet's main chain, either by extending the chain
// with new blocks, or switching to a better sidechain.  A sidechain for removed
// blocks (if any) is returned.  If relevantTxs is non-nil, the block marker for
// the latest block with processed transactions is updated for the new tip
// block.
func (w *Wallet) ChainSwitch(forest *SidechainForest, chain []*BlockNode, relevantTxs map[chainhash.Hash][]*wire.MsgTx) ([]*BlockNode, error) {
	const op errors.Op = "wallet.ChainSwitch"

	if len(chain) == 0 {
		return nil, errors.E(op, errors.Invalid, "zero-length chain")
	}

	chainTipChanges := &MainTipChangedNotification{
		AttachedBlocks: make([]*chainhash.Hash, 0, len(chain)),
		DetachedBlocks: nil,
		NewHeight:      int32(chain[len(chain)-1].Header.Height),
	}

	sideChainForkHeight := int32(chain[0].Header.Height)
	var prevChain []*BlockNode

	newWork := chain[len(chain)-1].workSum
	oldWork := new(big.Int)

	var watchOutPoints []wire.OutPoint

	err := walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

		tipHash, tipHeight := w.TxStore.MainChainTip(txmgrNs)

		if sideChainForkHeight <= tipHeight {
			chainTipChanges.DetachedBlocks = make([]*chainhash.Hash, tipHeight-sideChainForkHeight+1)
			prevChain = make([]*BlockNode, tipHeight-sideChainForkHeight+1)
			for i := tipHeight; i >= sideChainForkHeight; i-- {
				hash, err := w.TxStore.GetMainChainBlockHashForHeight(txmgrNs, i)
				if err != nil {
					return err
				}
				header, err := w.TxStore.GetBlockHeader(dbtx, &hash)
				if err != nil {
					return err
				}
				filter, err := w.TxStore.CFilter(dbtx, &hash)
				if err != nil {
					return err
				}

				// DetachedBlocks and prevChain are sorted in order of increasing heights.
				chainTipChanges.DetachedBlocks[i-sideChainForkHeight] = &hash
				prevChain[i-sideChainForkHeight] = NewBlockNode(header, &hash, filter)

				// For transaction notifications, the blocks are notified in reverse
				// height order.
				w.NtfnServer.notifyDetachedBlock(&hash)

				oldWork.Add(oldWork, blockchain.CalcWork(header.Bits))
			}

			if newWork.Cmp(oldWork) != 1 {
				return errors.Errorf("failed reorganize: sidechain ending at block %v has less total work "+
					"than the main chain tip block %v", chain[len(chain)-1].Hash, &tipHash)
			}

			// Remove blocks on the current main chain that are at or above the
			// height of the block that begins the side chain.
			err := w.TxStore.Rollback(txmgrNs, addrmgrNs, sideChainForkHeight)
			if err != nil {
				return err
			}
		}

		for _, n := range chain {
			if voteVersion(w.chainParams) < n.Header.StakeVersion {
				log.Warnf("Old vote version detected (v%v), please update your "+
					"wallet to the latest version.", voteVersion(w.chainParams))
			}

			watch, err := w.extendMainChain(op, dbtx, n.Header, n.Filter, relevantTxs[*n.Hash])
			if err != nil {
				return err
			}
			watchOutPoints = append(watchOutPoints, watch...)

			// Add the block hash to the notification.
			chainTipChanges.AttachedBlocks = append(chainTipChanges.AttachedBlocks, n.Hash)
		}

		if relevantTxs != nil {
			// To avoid skipped blocks, the marker is not advanced if there is a
			// gap between the existing rescan point (main chain fork point of
			// the current marker) and the first block attached in this chain
			// switch.
			r, err := w.rescanPoint(dbtx)
			if err != nil {
				return err
			}
			rHeader, err := w.TxStore.GetBlockHeader(dbtx, r)
			if err != nil {
				return err
			}
			if !(rHeader.Height+1 < chain[0].Header.Height) {
				marker := chain[len(chain)-1].Hash
				log.Debugf("Updating processed txs block marker to %v", marker)
				err := w.TxStore.UpdateProcessedTxsBlockMarker(dbtx, marker)
				if err != nil {
					return err
				}
			}
		}

		// Prune unmined transactions that don't belong on the extended chain.
		// An error here is not fatal and should just be logged.
		//
		// TODO: The stake difficulty passed here is not correct.  This must be
		// the difficulty of the next block, not the tip block.
		tip := chain[len(chain)-1]
		err := w.TxStore.PruneUnmined(dbtx, tip.Header.SBits)
		if err != nil {
			log.Errorf("Failed to prune unmined transactions when "+
				"connecting block height %v: %v", tip.Header.Height, err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.E(op, err)
	}

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		return w.watchFutureAddresses(tx)
	})
	if n, err := w.NetworkBackend(); err == nil && len(watchOutPoints) > 0 {
		err := n.LoadTxFilter(context.TODO(), false, nil, watchOutPoints)
		if err != nil {
			log.Errorf("Failed to watch outpoints: %v", err)
		}
	}

	forest.PruneTree(chain[0].Hash)
	forest.Prune(int32(chain[len(chain)-1].Header.Height), w.chainParams)

	w.NtfnServer.notifyMainChainTipChanged(chainTipChanges)
	w.NtfnServer.sendAttachedBlockNotification()

	return prevChain, nil
}

// AcceptMempoolTx adds a relevant unmined transaction to the wallet.
// If a network backend is associated with the wallet, it is updated
// with new addresses and unspent outpoints to watch.
func (w *Wallet) AcceptMempoolTx(tx *wire.MsgTx) error {
	const op errors.Op = "wallet.AcceptMempoolTx"
	var watchOutPoints []wire.OutPoint
	err := walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		rec, err := udb.NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			return err
		}

		// Prevent orphan votes from entering the wallet's unmined transaction
		// set.
		if isVote(&rec.MsgTx) {
			votedBlock, _ := stake.SSGenBlockVotedOn(&rec.MsgTx)
			tipBlock, _ := w.TxStore.MainChainTip(txmgrNs)
			if votedBlock != tipBlock {
				log.Debugf("Rejected unmined orphan vote %v which votes on block %v",
					&rec.Hash, &votedBlock)
				return nil
			}
		}

		watchOutPoints, err = w.processTransactionRecord(dbtx, rec, nil, nil)
		return err
	})
	if err != nil {
		return errors.E(op, err)
	}
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		return w.watchFutureAddresses(tx)
	})
	if err != nil {
		log.Errorf("Failed to watch for future address usage: %v", err)
	}
	if n, err := w.NetworkBackend(); err == nil && len(watchOutPoints) > 0 {
		err := n.LoadTxFilter(context.TODO(), false, nil, watchOutPoints)
		if err != nil {
			log.Errorf("Failed to watch outpoints: %v", err)
		}
	}
	return nil
}

func (w *Wallet) processSerializedTransaction(dbtx walletdb.ReadWriteTx, serializedTx []byte,
	header *wire.BlockHeader, blockMeta *udb.BlockMeta) (watchOutPoints []wire.OutPoint, err error) {

	const op errors.Op = "wallet.processSerializedTransaction"
	rec, err := udb.NewTxRecord(serializedTx, time.Now())
	if err != nil {
		return nil, errors.E(op, err)
	}
	return w.processTransactionRecord(dbtx, rec, header, blockMeta)
}

func (w *Wallet) processTransactionRecord(dbtx walletdb.ReadWriteTx, rec *udb.TxRecord,
	header *wire.BlockHeader, blockMeta *udb.BlockMeta) (watchOutPoints []wire.OutPoint, err error) {

	const op errors.Op = "wallet.processTransactionRecord"

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	stakemgrNs := dbtx.ReadWriteBucket(wstakemgrNamespaceKey)

	var txmgrNs walletdb.ReadWriteBucket
	if blockchain.IsSideTx(&rec.MsgTx) {
		txmgrNs = dbtx.ReadWriteBucket(wstxmgrNamespaceKey)
	} else {
		txmgrNs = dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
	}

	// At the moment all notified transactions are assumed to actually be
	// relevant.  This assumption will not hold true when SPV support is
	// added, but until then, simply insert the transaction because there
	// should either be one or more relevant inputs or outputs.
	if header == nil {
		err = w.TxStore.InsertMemPoolTx(txmgrNs, rec)
		if errors.Is(errors.Exist, err) {
			log.Warnf("Refusing to add unmined transaction %v since same "+
				"transaction already exists mined", &rec.Hash)
			return nil, nil
		}
	} else {
		err = w.TxStore.InsertMinedTx(txmgrNs, addrmgrNs, rec, &blockMeta.Hash)
	}
	if err != nil {
		return nil, errors.E(op, err)
	}

	// Handle incoming SStx; store them in the stake manager if we own
	// the OP_SSTX tagged out, except if we're operating as a stake pool
	// server. In that case, additionally consider the first commitment
	// output as well.
	if stake.IsSStx(&rec.MsgTx) {
		// Errors don't matter here.  If addrs is nil, the range below
		// does nothing.
		txOut := rec.MsgTx.TxOut[0]
		_, addrs, _, _ := txscript.ExtractPkScriptAddrs(txOut.Version,
			txOut.PkScript, w.chainParams)
		insert := false
		for _, addr := range addrs {
			if !w.Manager.ExistsHash160(addrmgrNs, addr.Hash160()[:]) {
				continue
			}

			// We are operating as a stake pool. The below
			// function will ONLY add the ticket into the
			// stake pool if it has been found within a
			// block.
			if header == nil {
				break
			}

			// At this point the ticket must be invalid, so insert it into the
			// list of invalid user tickets.
			err := w.StakeMgr.UpdateStakePoolUserInvalTickets(
				stakemgrNs, addr, &rec.Hash)
			if err != nil {
				log.Warnf("Failed to update pool user %v with "+
					"invalid ticket %v", addr.EncodeAddress(),
					rec.Hash)
			}
		}

		if insert {
			err := w.StakeMgr.InsertSStx(stakemgrNs, dosutil.NewTx(&rec.MsgTx))
			if err != nil {
				log.Errorf("Failed to insert SStx %v"+
					"into the stake store.", &rec.Hash)
			}
		}
	}

	// Handle input scripts that contain P2PKs that we care about.
	for i, input := range rec.MsgTx.TxIn {
		if txscript.IsMultisigSigScript(input.SignatureScript) {
			rs, err := txscript.MultisigRedeemScriptFromScriptSig(
				input.SignatureScript)
			if err != nil {
				return nil, err
			}

			class, addrs, _, err := txscript.ExtractPkScriptAddrs(
				txscript.DefaultScriptVersion, rs, w.chainParams)
			if err != nil {
				// Non-standard outputs are skipped.
				continue
			}
			if class != txscript.MultiSigTy {
				// This should never happen, but be paranoid.
				continue
			}

			isRelevant := false
			for _, addr := range addrs {
				ma, err := w.Manager.Address(addrmgrNs, addr)
				if err != nil {
					// Missing addresses are skipped.  Other errors should be
					// propagated.
					if errors.Is(errors.NotExist, err) {
						continue
					}
					return nil, errors.E(op, err)
				}
				isRelevant = true
				err = w.markUsedAddress(op, dbtx, ma)
				if err != nil {
					return nil, err
				}
				log.Debugf("Marked address %v used", addr)
			}

			// Add the script to the script databases.
			// TODO Markused script address? cj
			if isRelevant {
				err = w.TxStore.InsertTxScript(txmgrNs, rs)
				if err != nil {
					return nil, errors.E(op, err)
				}
				mscriptaddr, err := w.Manager.ImportScript(addrmgrNs, rs)
				switch {
				case errors.Is(errors.Exist, err): // Don't care if it's already there.
				case errors.Is(errors.Locked, err):
					log.Warnf("failed to attempt script importation "+
						"of incoming tx script %x because addrmgr "+
						"was locked", rs)
				case err == nil:
					if n, err := w.NetworkBackend(); err == nil {
						addr := mscriptaddr.Address()
						err := n.LoadTxFilter(context.TODO(),
							false, []dosutil.Address{addr}, nil)
						if err != nil {
							return nil, errors.E(op, err)
						}
					}
				default:
					return nil, errors.E(op, err)
				}
			}

			// If we're spending a multisig outpoint we know about,
			// update the outpoint. Inefficient because you deserialize
			// the entire multisig output info. Consider a specific
			// exists function in udb. The error here is skipped
			// because the absence of an multisignature output for
			// some script can not always be considered an error. For
			// example, the wallet might be rescanning as called from
			// the above function and so does not have the output
			// included yet.
			mso, err := w.TxStore.GetMultisigOutput(txmgrNs, &input.PreviousOutPoint)
			if mso != nil && err == nil {
				err = w.TxStore.SpendMultisigOut(txmgrNs, &input.PreviousOutPoint,
					rec.Hash, uint32(i))
				if err != nil {
					return nil, errors.E(op, err)
				}
			}
		}
	}

	// Check every output to determine whether it is controlled by a
	// wallet key.  If so, mark the output as a credit and mark
	// outpoints to watch.
	for i, output := range rec.MsgTx.TxOut {
		// Ignore unspendable outputs.
		if output.Value == 0 {
			continue
		}

		class, addrs, _, err := txscript.ExtractPkScriptAddrs(output.Version,
			output.PkScript, w.chainParams)
		if err != nil {
			// Non-standard outputs are skipped.
			continue
		}
		isStakeType := class == txscript.StakeSubmissionTy ||
			class == txscript.StakeSubChangeTy ||
			class == txscript.StakeGenTy ||
			class == txscript.StakeRevocationTy
		if isStakeType {
			class, err = txscript.GetStakeOutSubclass(output.PkScript)
			if err != nil {
				err = errors.E(op, errors.E(errors.Op("txscript.GetStakeOutSubclass"), err))
				log.Error(err)
				continue
			}
		}

		var tree int8
		if isStakeType {
			tree = 1
		}
		outpoint := wire.OutPoint{Hash: rec.Hash, Tree: tree}
		for _, addr := range addrs {
			ma, err := w.Manager.Address(addrmgrNs, addr)
			// Missing addresses are skipped.  Other errors should
			// be propagated.
			if errors.Is(errors.NotExist, err) {
				continue
			}
			if err != nil {
				return nil, errors.E(op, err)
			}
			err = w.TxStore.AddCredit(txmgrNs, rec, blockMeta,
				uint32(i), ma.Internal(), ma.Account())
			if err != nil {
				return nil, errors.E(op, err)
			}
			err = w.markUsedAddress(op, dbtx, ma)
			if err != nil {
				return nil, err
			}
			outpoint.Index = uint32(i)
			watchOutPoints = append(watchOutPoints, outpoint)
			log.Debugf("Marked address %v used", addr)
		}

		// Handle P2SH addresses that are multisignature scripts
		// with keys that we own.
		if class == txscript.ScriptHashTy {
			var expandedScript []byte
			for _, addr := range addrs {
				// Search both the script store in the tx store
				// and the address manager for the redeem script.
				var err error
				expandedScript, err = w.TxStore.GetTxScript(txmgrNs,
					addr.ScriptAddress())
				if errors.Is(errors.NotExist, err) {
					script, done, err := w.Manager.RedeemScript(addrmgrNs, addr)
					if err != nil {
						log.Debugf("failed to find redeemscript for "+
							"address %v in address manager: %v",
							addr.EncodeAddress(), err)
						continue
					}
					defer done()
					expandedScript = script
				} else if err != nil {
					return nil, errors.E(op, err)
				}
			}

			// Otherwise, extract the actual addresses and
			// see if any belong to us.
			expClass, multisigAddrs, _, err := txscript.ExtractPkScriptAddrs(
				txscript.DefaultScriptVersion,
				expandedScript,
				w.chainParams)
			if err != nil {
				return nil, errors.E(op, errors.E(errors.Op("txscript.ExtractPkScriptAddrs"), err))
			}

			// Skip non-multisig scripts.
			if expClass != txscript.MultiSigTy {
				continue
			}

			for _, maddr := range multisigAddrs {
				_, err := w.Manager.Address(addrmgrNs, maddr)
				// An address we own; handle accordingly.
				if err == nil {
					err := w.TxStore.AddMultisigOut(
						txmgrNs, rec, blockMeta, uint32(i))
					if err != nil {
						// This will throw if there are multiple private keys
						// for this multisignature output owned by the wallet,
						// so it's routed to debug.
						log.Debugf("unable to add multisignature output: %v", err)
					}
				}
			}
		}
	}

	// Send notification of mined or unmined transaction to any interested
	// clients.
	//
	// TODO: Avoid the extra db hits.
	if header == nil {
		details, err := w.TxStore.UniqueTxDetails(txmgrNs, &rec.Hash, nil)
		if err != nil {
			log.Errorf("Cannot query transaction details for notifiation: %v", err)
		} else {
			w.NtfnServer.notifyUnminedTransaction(dbtx, details)
		}
	} else {
		details, err := w.TxStore.UniqueTxDetails(txmgrNs, &rec.Hash, &blockMeta.Block)
		if err != nil {
			log.Errorf("Cannot query transaction details for notifiation: %v", err)
		} else {
			w.NtfnServer.notifyMinedTransaction(dbtx, details, blockMeta)
		}
	}

	//if blockchain.IsActionTx(&rec.MsgTx) {
	//	value := new(big.Int).Add(rec.MsgTx.TxIn[0].PreviousOutPoint.Hash.Big(), big.NewInt(1))
	//	if err = txmgrNs.Put(rootLastNonce, value.Bytes()); err != nil {
	//		return nil, err
	//	}
	//}

	return watchOutPoints, nil
}

// selectOwnedTickets returns a slice of tickets hashes from the tickets
// argument that are owned by the wallet.
//
// Because votes must be created for tickets tracked by both the transaction
// manager and the stake manager, this function checks both.
func selectOwnedTickets(w *Wallet, dbtx walletdb.ReadTx, tickets []*chainhash.Hash) []*chainhash.Hash {
	var owned []*chainhash.Hash
	for _, ticketHash := range tickets {
		if w.TxStore.OwnTicket(dbtx, ticketHash) || w.StakeMgr.OwnTicket(ticketHash) {
			owned = append(owned, ticketHash)
		}
	}
	return owned
}
