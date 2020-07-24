// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"gogs.doschain.org/doschain/doswallet/wallet/txauthor"
	"math/big"
	"strings"
	"sync"
	"time"

	"gogs.doschain.org/doschain/dosd/blockchain"
	"gogs.doschain.org/doschain/dosd/chaincfg"
	"gogs.doschain.org/doschain/dosd/chaincfg/chainhash"
	"gogs.doschain.org/doschain/dosd/dosec"
	"gogs.doschain.org/doschain/dosd/dosjson"
	"gogs.doschain.org/doschain/dosd/dosutil"
	"gogs.doschain.org/doschain/dosd/hdkeychain"
	"gogs.doschain.org/doschain/dosd/rpcclient"
	"gogs.doschain.org/doschain/dosd/txscript"
	"gogs.doschain.org/doschain/dosd/wire"
	"gogs.doschain.org/doschain/doswallet/chain"
	"gogs.doschain.org/doschain/doswallet/errors"
	"gogs.doschain.org/doschain/doswallet/internal/helpers"
	"gogs.doschain.org/doschain/doswallet/p2p"
	ver "gogs.doschain.org/doschain/doswallet/version"
	"gogs.doschain.org/doschain/doswallet/wallet"
	"gogs.doschain.org/doschain/doswallet/wallet/udb"
)

// API version constants
const (
	jsonrpcSemverString = "5.0.0"
	jsonrpcSemverMajor  = 5
	jsonrpcSemverMinor  = 0
	jsonrpcSemverPatch  = 0
)

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}

// the registered rpc handlers
var handlers = map[string]handler{
	// Reference implementation wallet methods (implemented)
	"accountaddressindex":     {fn: accountAddressIndex},
	"accountsyncaddressindex": {fn: accountSyncAddressIndex},
	"addmultisigaddress":      {fn: addMultiSigAddress},
	"consolidate":             {fn: consolidate},
	"createmultisig":          {fn: createMultiSig},
	"dumpprivkey":             {fn: dumpPrivKey},
	"getaccount":              {fn: getAccount},
	"getaccountaddress":       {fn: getAccountAddress},
	"getaddressesbyaccount":   {fn: getAddressesByAccount},
	"getbalance":              {fn: getBalance},
	"getbestblockhash":        {fn: getBestBlockHash},
	"getblockcount":           {fn: getBlockCount},
	"getinfo":                 {fn: getInfo},
	"getmasterpubkey":         {fn: getMasterPubkey},
	"getmultisigoutinfo":      {fn: getMultisigOutInfo},
	"getnewaddress":           {fn: getNewAddress},
	"getrawchangeaddress":     {fn: getRawChangeAddress},
	"getreceivedbyaccount":    {fn: getReceivedByAccount},
	"getreceivedbyaddress":    {fn: getReceivedByAddress},
	"getstakeinfo":            {fn: getStakeInfo},
	"gettransaction":          {fn: getTransaction},
	"getwalletfee":            {fn: getWalletFee},
	"help":                    {fn: help},
	"importprivkey":           {fn: importPrivKey},
	"importscript":            {fn: importScript},
	"keypoolrefill":           {fn: keypoolRefill},
	"listaccounts":            {fn: listAccounts},
	"listlockunspent":         {fn: listLockUnspent},
	"listreceivedbyaccount":   {fn: listReceivedByAccount},
	"listreceivedbyaddress":   {fn: listReceivedByAddress},
	"listsinceblock":          {fn: listSinceBlock},
	"listscripts":             {fn: listScripts},
	"listtransactions":        {fn: listTransactions},
	"listunspent":             {fn: listUnspent},
	"lockunspent":             {fn: lockUnspent},
	"rescanwallet":            {fn: rescanWallet},
	"sendfrom":                {fn: sendFrom},
	"sendmany":                {fn: sendMany},
	"sendtoaddress":           {fn: sendToAddress},
	"sendtomultisig":          {fn: sendToMultiSig},
	"transfer":                {fn: transfer},
	"settxfee":                {fn: setTxFee},
	"signmessage":             {fn: signMessage},
	"signrawtransaction":      {fn: signRawTransaction},
	"signrawtransactions":     {fn: signRawTransactions},
	"sweepaccount":            {fn: sweepAccount},
	"redeemmultisigout":       {fn: redeemMultiSigOut},
	"redeemmultisigouts":      {fn: redeemMultiSigOuts},
	"validateaddress":         {fn: validateAddress},
	"verifymessage":           {fn: verifyMessage},
	"version":                 {fn: version},
	"walletinfo":              {fn: walletInfo},
	"walletlock":              {fn: walletLock},
	"walletpassphrase":        {fn: walletPassphrase},
	"walletpassphrasechange":  {fn: walletPassphraseChange},

	// Extensions to the reference client JSON-RPC API
	"getbestblock":     {fn: getBestBlock},
	"createnewaccount": {fn: createNewAccount},
	// This was an extension but the reference implementation added it as
	// well, but with a different API (no account parameter).  It's listed
	// here because it hasn't been update to use the reference
	// implemenation's API.
	"getunconfirmedbalance":   {fn: getUnconfirmedBalance},
	"listaddresstransactions": {fn: listAddressTransactions},
	"listalltransactions":     {fn: listAllTransactions},
	"renameaccount":           {fn: renameAccount},
	"walletislocked":          {fn: walletIsLocked},

	// Reference implementation methods (still unimplemented)
	"backupwallet":         {fn: unimplemented, noHelp: true},
	"getwalletinfo":        {fn: unimplemented, noHelp: true},
	"importwallet":         {fn: unimplemented, noHelp: true},
	"listaddressgroupings": {fn: unimplemented, noHelp: true},

	// Reference methods which can't be implemented by dcrwallet due to
	// design decision differences
	"dumpwallet":    {fn: unsupported, noHelp: true},
	"encryptwallet": {fn: unsupported, noHelp: true},
	"move":          {fn: unsupported, noHelp: true},
	"setaccount":    {fn: unsupported, noHelp: true},
}

// unimplemented handles an unimplemented RPC request with the
// appropiate error.
func unimplemented(*Server, interface{}) (interface{}, error) {
	return nil, &dosjson.RPCError{
		Code:    dosjson.ErrRPCUnimplemented,
		Message: "Method unimplemented",
	}
}

// unsupported handles a standard bitcoind RPC request which is
// unsupported by dcrwallet due to design differences.
func unsupported(*Server, interface{}) (interface{}, error) {
	return nil, &dosjson.RPCError{
		Code:    -1,
		Message: "Request unsupported by dcrwallet",
	}
}

// lazyHandler is a closure over a requestHandler or passthrough request with
// the RPC server's wallet and chain server variables as part of the closure
// context.
type lazyHandler func() (interface{}, *dosjson.RPCError)

// lazyApplyHandler looks up the best request handler func for the method,
// returning a closure that will execute it with the (required) wallet and
// (optional) consensus RPC server.  If no handlers are found and the
// chainClient is not nil, the returned handler performs RPC passthrough.
func lazyApplyHandler(s *Server, request *dosjson.Request) lazyHandler {
	handlerData, ok := handlers[request.Method]
	if !ok {
		return func() (interface{}, *dosjson.RPCError) {
			// Attempt RPC passthrough if possible
			n, ok := s.walletLoader.NetworkBackend()
			if !ok {
				return nil, errRPCClientNotConnected
			}
			chainClient, err := chain.RPCClientFromBackend(n)
			if err != nil {
				return nil, rpcErrorf(dosjson.ErrRPCClientNotConnected, "RPC passthrough requires dcrd RPC synchronization")
			}
			resp, err := chainClient.RawRequest(request.Method, request.Params)
			if err != nil {
				return nil, convertError(err)
			}
			return &resp, nil
		}
	}

	return func() (interface{}, *dosjson.RPCError) {
		cmd, err := dosjson.UnmarshalCmd(request)
		if err != nil {
			return nil, dosjson.ErrRPCInvalidRequest
		}

		resp, err := handlerData.fn(s, cmd)
		if err != nil {
			return nil, convertError(err)
		}
		return resp, nil
	}
}

// makeResponse makes the JSON-RPC response struct for the result and error
// returned by a requestHandler.  The returned response is not ready for
// marshaling and sending off to a client, but must be
func makeResponse(id, result interface{}, err error) dosjson.Response {
	idPtr := idPointer(id)
	if err != nil {
		return dosjson.Response{
			ID:    idPtr,
			Error: convertError(err),
		}
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return dosjson.Response{
			ID: idPtr,
			Error: &dosjson.RPCError{
				Code:    dosjson.ErrRPCInternal.Code,
				Message: "Unexpected error marshalling result",
			},
		}
	}
	return dosjson.Response{
		ID:     idPtr,
		Result: json.RawMessage(resultBytes),
	}
}

// accountAddressIndex returns the next address index for the passed
// account and branch.
func accountAddressIndex(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.AccountAddressIndexCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(cmd.Account)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	extChild, intChild, err := w.BIP0044BranchNextIndexes(account)
	if err != nil {
		return nil, err
	}
	switch uint32(cmd.Branch) {
	case udb.ExternalBranch:
		return extChild, nil
	case udb.InternalBranch:
		return intChild, nil
	default:
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "invalid branch %v", cmd.Branch)
	}
}

// accountSyncAddressIndex synchronizes the address manager and local address
// pool for some account and branch to the passed index. If the current pool
// index is beyond the passed index, an error is returned. If the passed index
// is the same as the current pool index, nothing is returned. If the syncing
// is successful, nothing is returned.
func accountSyncAddressIndex(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.AccountSyncAddressIndexCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(cmd.Account)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	branch := uint32(cmd.Branch)
	index := uint32(cmd.Index)

	if index >= hdkeychain.HardenedKeyStart {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter,
			"child index %d exceeds the maximum child index for an account", index)
	}

	// Additional addresses need to be watched.  Since addresses are derived
	// based on the last used address, this RPC no longer changes the child
	// indexes that new addresses are derived from.
	return nil, w.ExtendWatchedAddresses(account, branch, index)
}

func makeMultiSigScript(w *wallet.Wallet, keys []string, nRequired int) ([]byte, error) {
	keysesPrecious := make([]*dosutil.AddressSecpPubKey, len(keys))

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, a := range keys {
		// try to parse as pubkey address
		a, err := decodeAddress(a, w.ChainParams())
		if err != nil {
			return nil, err
		}

		switch addr := a.(type) {
		case *dosutil.AddressSecpPubKey:
			keysesPrecious[i] = addr
		default:
			pubKey, err := w.PubKeyForAddress(addr)
			if err != nil {
				if errors.Is(errors.NotExist, err) {
					return nil, errAddressNotInWallet
				}
				return nil, err
			}
			if dosec.SignatureType(pubKey.GetType()) != dosec.STEcdsaSecp256k1 {
				return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter,
					"only secp256k1 pubkeys are currently supported")
			}
			pubKeyAddr, err := dosutil.NewAddressSecpPubKey(
				pubKey.Serialize(), w.ChainParams())
			if err != nil {
				return nil, rpcError(dosjson.ErrRPCInvalidAddressOrKey, err)
			}
			keysesPrecious[i] = pubKeyAddr
		}
	}

	return txscript.MultiSigScript(keysesPrecious, nRequired)
}

// addMultiSigAddress handles an addmultisigaddress request by adding a
// multisig address to the given wallet.
func addMultiSigAddress(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.AddMultisigAddressCmd)
	// If an account is specified, ensure that is the imported account.
	if cmd.Account != nil && *cmd.Account != udb.ImportedAddrAccountName {
		return nil, errNotImportedAccount
	}

	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	secp256k1Addrs := make([]dosutil.Address, len(cmd.Keys))
	for i, k := range cmd.Keys {
		addr, err := decodeAddress(k, w.ChainParams())
		if err != nil {
			return nil, err
		}
		secp256k1Addrs[i] = addr
	}

	script, err := w.MakeSecp256k1MultiSigScript(secp256k1Addrs, cmd.NRequired)
	if err != nil {
		return nil, err
	}

	p2shAddr, err := w.ImportP2SHRedeemScript(script)
	if err != nil {
		return nil, err
	}

	n, ok := s.walletLoader.NetworkBackend()
	if !ok {
		return nil, errNoNetwork
	}
	err = n.LoadTxFilter(context.TODO(), false, []dosutil.Address{p2shAddr}, nil)
	if err != nil {
		return nil, err
	}

	return p2shAddr.EncodeAddress(), nil
}

// consolidate handles a consolidate request by returning attempting to compress
// as many inputs as given and then returning the txHash and error.
func consolidate(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ConsolidateCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account := uint32(udb.DefaultAccountNum)
	var err error
	if cmd.Account != nil {
		account, err = w.AccountNumber(*cmd.Account)
		if err != nil {
			if errors.Is(errors.NotExist, err) {
				return nil, errAccountNotFound
			}
			return nil, err
		}
	}

	// Set change address if specified.
	var changeAddr dosutil.Address
	if cmd.Address != nil {
		if *cmd.Address != "" {
			addr, err := decodeAddress(*cmd.Address, w.ChainParams())
			if err != nil {
				return nil, err
			}
			changeAddr = addr
		}
	}

	// TODO In the future this should take the optional account and
	// only consolidate UTXOs found within that account.
	txHash, err := w.Consolidate(cmd.Inputs, account, changeAddr)
	if err != nil {
		return nil, err
	}

	return txHash.String(), nil
}

// createMultiSig handles an createmultisig request by returning a
// multisig address for the given inputs.
func createMultiSig(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.CreateMultisigCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	script, err := makeMultiSigScript(w, cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, err
	}

	address, err := dosutil.NewAddressScriptHash(script, w.ChainParams())
	if err != nil {
		return nil, err
	}

	return dosjson.CreateMultiSigResult{
		Address:      address.EncodeAddress(),
		RedeemScript: hex.EncodeToString(script),
	}, nil
}

// dumpPrivKey handles a dumpprivkey request with the private key
// for a single address, or an appropiate error if the wallet
// is locked.
func dumpPrivKey(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.DumpPrivKeyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	key, err := w.DumpWIFPrivateKey(addr)
	if err != nil {
		if errors.Is(errors.Locked, err) {
			return nil, errWalletUnlockNeeded
		}
		return nil, err
	}
	return key, nil
}

// getAddressesByAccount handles a getaddressesbyaccount request by returning
// all addresses for an account, or an error if the requested account does
// not exist.
func getAddressesByAccount(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetAddressesByAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(cmd.Account)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	// Find the next child address indexes for the account.
	endExt, endInt, err := w.BIP0044BranchNextIndexes(account)
	if err != nil {
		return nil, err
	}

	// Nothing to do if we have no addresses.
	if endExt+endInt == 0 {
		return nil, nil
	}

	// Derive the addresses.
	addrsStr := make([]string, endInt+endExt)
	addrsExt, err := w.AccountBranchAddressRange(account, udb.ExternalBranch, 0, endExt)
	if err != nil {
		return nil, err
	}
	for i := range addrsExt {
		addrsStr[i] = addrsExt[i].EncodeAddress()
	}
	addrsInt, err := w.AccountBranchAddressRange(account, udb.InternalBranch, 0, endInt)
	if err != nil {
		return nil, err
	}
	for i := range addrsInt {
		addrsStr[i+int(endExt)] = addrsInt[i].EncodeAddress()
	}

	return addrsStr, nil
}

// getBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func getBalance(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetBalanceCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "minconf must be non-negative")
	}

	accountName := "*"
	if cmd.Account != nil {
		accountName = *cmd.Account
	}

	blockHash, _ := w.MainChainTip()
	result := dosjson.GetBalanceResult{
		BlockHash: blockHash.String(),
	}

	if accountName == "*" {
		balances, err := w.CalculateAccountBalances(int32(*cmd.MinConf))
		if err != nil {
			return nil, err
		}

		var (
			totImmatureCoinbase dosutil.Amount
			totImmatureStakegen dosutil.Amount
			totLocked           dosutil.Amount
			totSpendable        dosutil.Amount
			totUnconfirmed      dosutil.Amount
			totVotingAuthority  dosutil.Amount
			cumTot              dosutil.Amount
		)

		balancesLen := uint32(len(balances))
		result.Balances = make([]dosjson.GetAccountBalanceResult, balancesLen)

		for _, bal := range balances {
			accountName, err := w.AccountName(bal.Account)
			if err != nil {
				// Expect account lookup to succeed
				if errors.Is(errors.NotExist, err) {
					return nil, rpcError(dosjson.ErrRPCInternal.Code, err)
				}
				return nil, err
			}

			totImmatureCoinbase += bal.ImmatureCoinbaseRewards
			totImmatureStakegen += bal.ImmatureStakeGeneration
			totLocked += bal.LockedByTickets
			totSpendable += bal.Spendable
			totUnconfirmed += bal.Unconfirmed
			totVotingAuthority += bal.VotingAuthority
			cumTot += bal.Total

			json := dosjson.GetAccountBalanceResult{
				AccountName:             accountName,
				ImmatureCoinbaseRewards: bal.ImmatureCoinbaseRewards.ToCoin(),
				ImmatureStakeGeneration: bal.ImmatureStakeGeneration.ToCoin(),
				LockedByTickets:         bal.LockedByTickets.ToCoin(),
				Spendable:               bal.Spendable.ToCoin(),
				Total:                   bal.Total.ToCoin(),
				Unconfirmed:             bal.Unconfirmed.ToCoin(),
				VotingAuthority:         bal.VotingAuthority.ToCoin(),
			}

			var balIdx uint32
			if bal.Account == udb.ImportedAddrAccount {
				balIdx = balancesLen - 1
			} else {
				balIdx = bal.Account
			}
			result.Balances[balIdx] = json
		}

		result.TotalImmatureCoinbaseRewards = totImmatureCoinbase.ToCoin()
		result.TotalImmatureStakeGeneration = totImmatureStakegen.ToCoin()
		result.TotalLockedByTickets = totLocked.ToCoin()
		result.TotalSpendable = totSpendable.ToCoin()
		result.TotalUnconfirmed = totUnconfirmed.ToCoin()
		result.TotalVotingAuthority = totVotingAuthority.ToCoin()
		result.CumulativeTotal = cumTot.ToCoin()
	} else {
		account, err := w.AccountNumber(accountName)
		if err != nil {
			if errors.Is(errors.NotExist, err) {
				return nil, errAccountNotFound
			}
			return nil, err
		}

		bal, err := w.CalculateAccountBalance(account, int32(*cmd.MinConf))
		if err != nil {
			// Expect account lookup to succeed
			if errors.Is(errors.NotExist, err) {
				return nil, rpcError(dosjson.ErrRPCInternal.Code, err)
			}
			return nil, err
		}
		json := dosjson.GetAccountBalanceResult{
			AccountName:             accountName,
			ImmatureCoinbaseRewards: bal.ImmatureCoinbaseRewards.ToCoin(),
			ImmatureStakeGeneration: bal.ImmatureStakeGeneration.ToCoin(),
			LockedByTickets:         bal.LockedByTickets.ToCoin(),
			Spendable:               bal.Spendable.ToCoin(),
			Total:                   bal.Total.ToCoin(),
			Unconfirmed:             bal.Unconfirmed.ToCoin(),
			VotingAuthority:         bal.VotingAuthority.ToCoin(),
		}
		result.Balances = append(result.Balances, json)
	}

	return result, nil
}

// getBestBlock handles a getbestblock request by returning a JSON object
// with the height and hash of the most recently processed block.
func getBestBlock(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	hash, height := w.MainChainTip()
	result := &dosjson.GetBestBlockResult{
		Hash:   hash.String(),
		Height: int64(height),
	}
	return result, nil
}

// getBestBlockHash handles a getbestblockhash request by returning the hash
// of the most recently processed block.
func getBestBlockHash(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	hash, _ := w.MainChainTip()
	return hash.String(), nil
}

// getBlockCount handles a getblockcount request by returning the chain height
// of the most recently processed block.
func getBlockCount(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	_, height := w.MainChainTip()
	return height, nil
}

// difficultyRatio returns the proof-of-work difficulty as a multiple of the
// minimum difficulty using the passed bits field from the header of a block.
func difficultyRatio(bits uint32, params *chaincfg.Params) float64 {
	max := blockchain.CompactToBig(params.PowLimitBits)
	target := blockchain.CompactToBig(bits)
	ratio, _ := new(big.Rat).SetFrac(max, target).Float64()
	return ratio
}

// getInfo handles a getinfo request by returning a structure containing
// information about the current state of the wallet.
func getInfo(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	tipHash, tipHeight := w.MainChainTip()
	tipHeader, err := w.BlockHeader(&tipHash)
	if err != nil {
		return nil, err
	}

	balances, err := w.CalculateAccountBalances(1)
	if err != nil {
		return nil, err
	}
	var spendableBalance dosutil.Amount
	for _, balance := range balances {
		spendableBalance += balance.Spendable
	}

	info := &dosjson.InfoWalletResult{
		Version:         ver.Integer,
		ProtocolVersion: int32(p2p.Pver),
		WalletVersion:   ver.Integer,
		Balance:         spendableBalance.ToCoin(),
		Blocks:          tipHeight,
		TimeOffset:      0,
		Connections:     0,
		Proxy:           "",
		Difficulty:      difficultyRatio(tipHeader.Bits, w.ChainParams()),
		TestNet:         w.ChainParams().Net == wire.TestNet3,
		KeypoolOldest:   0,
		KeypoolSize:     0,
		UnlockedUntil:   0,
		PaytxFee:        w.RelayFee().ToCoin(),
		RelayFee:        0,
		Errors:          "",
	}

	n, _ := s.walletLoader.NetworkBackend()
	if chainClient, err := chain.RPCClientFromBackend(n); err == nil {
		consensusInfo, err := chainClient.GetInfo()
		if err != nil {
			return nil, err
		}
		info.Version = consensusInfo.Version
		info.ProtocolVersion = consensusInfo.ProtocolVersion
		info.TimeOffset = consensusInfo.TimeOffset
		info.Connections = consensusInfo.Connections
		info.Proxy = consensusInfo.Proxy
		info.RelayFee = consensusInfo.RelayFee
		info.Errors = consensusInfo.Errors
	}

	return info, nil
}

func decodeAddress(s string, params *chaincfg.Params) (dosutil.Address, error) {
	// Secp256k1 pubkey as a string, handle differently.
	if len(s) == 66 || len(s) == 130 {
		pubKeyBytes, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		pubKeyAddr, err := dosutil.NewAddressSecpPubKey(pubKeyBytes,
			params)
		if err != nil {
			return nil, err
		}

		return pubKeyAddr, nil
	}

	addr, err := dosutil.DecodeAddress(s)
	if err != nil {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidAddressOrKey,
			"invalid address %q: decode failed: %#q", s, err)
	}
	if !addr.IsForNet(params) {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidAddressOrKey,
			"invalid address %q: not intended for use on %s", s, params.Name)
	}
	return addr, nil
}

// getAccount handles a getaccount request by returning the account name
// associated with a single address.
func getAccount(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	// Fetch the associated account
	account, err := w.AccountOfAddress(addr)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAddressNotInWallet
		}
		return nil, err
	}

	acctName, err := w.AccountName(account)
	if err != nil {
		return nil, err
	}
	return acctName, nil
}

// getAccountAddress handles a getaccountaddress by returning the most
// recently-created chained address that has not yet been used (does not yet
// appear in the blockchain, or any tx that has arrived in the dcrd mempool).
// If the most recently-requested address has been used, a new address (the
// next chained address in the keypool) is used.  This can fail if the keypool
// runs out (and will return dosjson.ErrRPCWalletKeypoolRanOut if that happens).
func getAccountAddress(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetAccountAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(cmd.Account)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAccountNotFound
		}
		return nil, err
	}
	addr, err := w.CurrentAddress(account)
	if err != nil {
		// Expect account lookup to succeed
		if errors.Is(errors.NotExist, err) {
			return nil, rpcError(dosjson.ErrRPCInternal.Code, err)
		}
		return nil, err
	}

	return addr.EncodeAddress(), nil
}

// getUnconfirmedBalance handles a getunconfirmedbalance extension request
// by returning the current unconfirmed balance of an account.
func getUnconfirmedBalance(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetUnconfirmedBalanceCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.AccountNumber(acctName)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAccountNotFound
		}
		return nil, err
	}
	bals, err := w.CalculateAccountBalance(account, 1)
	if err != nil {
		// Expect account lookup to succeed
		if errors.Is(errors.NotExist, err) {
			return nil, rpcError(dosjson.ErrRPCInternal.Code, err)
		}
		return nil, err
	}

	return (bals.Total - bals.Spendable).ToCoin(), nil
}

// importPrivKey handles an importprivkey request by parsing
// a WIF-encoded private key and adding it to an account.
func importPrivKey(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ImportPrivKeyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	rescan := true
	if cmd.Rescan != nil {
		rescan = *cmd.Rescan
	}
	scanFrom := int32(0)
	if cmd.ScanFrom != nil {
		scanFrom = int32(*cmd.ScanFrom)
	}
	n, ok := s.walletLoader.NetworkBackend()
	if rescan && !ok {
		return nil, errNoNetwork
	}

	// Ensure that private keys are only imported to the correct account.
	//
	// Yes, Label is the account name.
	if cmd.Label != nil && *cmd.Label != udb.ImportedAddrAccountName {
		return nil, errNotImportedAccount
	}

	wif, err := dosutil.DecodeWIF(cmd.PrivKey)
	if err != nil {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidAddressOrKey, "WIF decode failed: %v", err)
	}
	if !wif.IsForNet(w.ChainParams()) {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidAddressOrKey, "key is not intended for %s", w.ChainParams().Name)
	}

	// Import the private key, handling any errors.
	_, err = w.ImportPrivateKey(wif)
	if err != nil {
		switch {
		case errors.Is(errors.Exist, err):
			// Do not return duplicate key errors to the client.
			return nil, nil
		case errors.Is(errors.Locked, err):
			return nil, errWalletUnlockNeeded
		default:
			return nil, err
		}
	}

	if rescan {
		// TODO: This is not synchronized with process shutdown and
		// will cause panics when the DB is closed mid-transaction.
		go w.RescanFromHeight(context.Background(), n, scanFrom)
	}

	return nil, nil
}

// importScript imports a redeem script for a P2SH output.
func importScript(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ImportScriptCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	rescan := true
	if cmd.Rescan != nil {
		rescan = *cmd.Rescan
	}
	scanFrom := int32(0)
	if cmd.ScanFrom != nil {
		scanFrom = int32(*cmd.ScanFrom)
	}
	n, ok := s.walletLoader.NetworkBackend()
	if rescan && !ok {
		return nil, errNoNetwork
	}

	rs, err := hex.DecodeString(cmd.Hex)
	if err != nil {
		return nil, rpcError(dosjson.ErrRPCDecodeHexString, err)
	}
	if len(rs) == 0 {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "empty script")
	}

	err = w.ImportScript(rs)
	if err != nil {
		switch {
		case errors.Is(errors.Exist, err):
			// Do not return duplicate script errors to the client.
			return nil, nil
		case errors.Is(errors.Locked, err):
			return nil, errWalletUnlockNeeded
		default:
			return nil, err
		}
	}

	if rescan {
		// TODO: This is not synchronized with process shutdown and
		// will cause panics when the DB is closed mid-transaction.
		go w.RescanFromHeight(context.Background(), n, scanFrom)
	}

	return nil, nil
}

// keypoolRefill handles the keypoolrefill command.  dcrwallet generates
// deterministic addresses rather than using a keypool, so this method does
// nothing.
func keypoolRefill(s *Server, icmd interface{}) (interface{}, error) {
	return nil, nil
}

// createNewAccount handles a createnewaccount request by creating and
// returning a new account. If the last account has no transaction history
// as per BIP 0044 a new account cannot be created so an error will be returned.
func createNewAccount(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.CreateNewAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// The wildcard * is reserved by the rpc server with the special meaning
	// of "all accounts", so disallow naming accounts to this string.
	if cmd.Account == "*" {
		return nil, errReservedAccountName
	}

	_, err := w.NextAccount(cmd.Account)
	if err != nil {
		if errors.Is(errors.Locked, err) {
			return nil, rpcErrorf(dosjson.ErrRPCWalletUnlockNeeded, "creating new accounts requires an unlocked wallet")
		}
		return nil, err
	}
	return nil, nil
}

// renameAccount handles a renameaccount request by renaming an account.
// If the account does not exist an appropiate error will be returned.
func renameAccount(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.RenameAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// The wildcard * is reserved by the rpc server with the special meaning
	// of "all accounts", so disallow naming accounts to this string.
	if cmd.NewAccount == "*" {
		return nil, errReservedAccountName
	}

	// Check that given account exists
	account, err := w.AccountNumber(cmd.OldAccount)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAccountNotFound
		}
		return nil, err
	}
	err = w.RenameAccount(account, cmd.NewAccount)
	return nil, err
}

// getMultisigOutInfo displays information about a given multisignature
// output.
func getMultisigOutInfo(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetMultisigOutInfoCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	hash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, rpcError(dosjson.ErrRPCDecodeHexString, err)
	}

	// Multisig outs are always in TxTreeRegular.
	op := &wire.OutPoint{
		Hash:  *hash,
		Index: cmd.Index,
		Tree:  wire.TxTreeRegular,
	}

	p2shOutput, err := w.FetchP2SHMultiSigOutput(op)
	if err != nil {
		return nil, err
	}

	// Get the list of pubkeys required to sign.
	_, pubkeyAddrs, _, err := txscript.ExtractPkScriptAddrs(
		txscript.DefaultScriptVersion, p2shOutput.RedeemScript,
		w.ChainParams())
	if err != nil {
		return nil, err
	}
	pubkeys := make([]string, 0, len(pubkeyAddrs))
	for _, pka := range pubkeyAddrs {
		pubkeys = append(pubkeys, hex.EncodeToString(pka.ScriptAddress()))
	}

	result := &dosjson.GetMultisigOutInfoResult{
		Address:      p2shOutput.P2SHAddress.EncodeAddress(),
		RedeemScript: hex.EncodeToString(p2shOutput.RedeemScript),
		M:            p2shOutput.M,
		N:            p2shOutput.N,
		Pubkeys:      pubkeys,
		TxHash:       p2shOutput.OutPoint.Hash.String(),
		Amount:       p2shOutput.OutputAmount.ToCoin(),
	}
	if !p2shOutput.ContainingBlock.None() {
		result.BlockHeight = uint32(p2shOutput.ContainingBlock.Height)
		result.BlockHash = p2shOutput.ContainingBlock.Hash.String()
	}
	if p2shOutput.Redeemer != nil {
		result.Spent = true
		result.SpentBy = p2shOutput.Redeemer.TxHash.String()
		result.SpentByIndex = p2shOutput.Redeemer.InputIndex
	}
	return result, nil
}

// getNewAddress handles a getnewaddress request by returning a new
// address for an account.  If the account does not exist an appropiate
// error is returned.
func getNewAddress(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetNewAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var callOpts []wallet.NextAddressCallOption
	if cmd.GapPolicy != nil {
		switch *cmd.GapPolicy {
		case "":
		case "error":
			callOpts = append(callOpts, wallet.WithGapPolicyError())
		case "ignore":
			callOpts = append(callOpts, wallet.WithGapPolicyIgnore())
		case "wrap":
			callOpts = append(callOpts, wallet.WithGapPolicyWrap())
		default:
			return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "unknown gap policy %q", *cmd.GapPolicy)
		}
	}

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.AccountNumber(acctName)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	addr, err := w.NewExternalAddress(account, callOpts...)
	if err != nil {
		return nil, err
	}
	return addr.EncodeAddress(), nil
}

// getRawChangeAddress handles a getrawchangeaddress request by creating
// and returning a new change address for an account.
//
// Note: bitcoind allows specifying the account as an optional parameter,
// but ignores the parameter.
func getRawChangeAddress(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetRawChangeAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.AccountNumber(acctName)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	addr, err := w.NewChangeAddress(account)
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// getReceivedByAccount handles a getreceivedbyaccount request by returning
// the total amount received by addresses of an account.
func getReceivedByAccount(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetReceivedByAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account, err := w.AccountNumber(cmd.Account)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	// TODO: This is more inefficient that it could be, but the entire
	// algorithm is already dominated by reading every transaction in the
	// wallet's history.
	results, err := w.TotalReceivedForAccounts(int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}
	acctIndex := int(account)
	if account == udb.ImportedAddrAccount {
		acctIndex = len(results) - 1
	}
	return results[acctIndex].TotalReceived.ToCoin(), nil
}

// getReceivedByAddress handles a getreceivedbyaddress request by returning
// the total amount received by a single address.
func getReceivedByAddress(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetReceivedByAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}
	total, err := w.TotalReceivedForAddr(addr, int32(*cmd.MinConf))
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAddressNotInWallet
		}
		return nil, err
	}

	return total.ToCoin(), nil
}

// getMasterPubkey handles a getmasterpubkey request by returning the wallet
// master pubkey encoded as a string.
func getMasterPubkey(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetMasterPubkeyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// If no account is passed, we provide the extended public key
	// for the default account number.
	account := uint32(udb.DefaultAccountNum)
	if cmd.Account != nil {
		var err error
		account, err = w.AccountNumber(*cmd.Account)
		if err != nil {
			if errors.Is(errors.NotExist, err) {
				return nil, errAccountNotFound
			}
			return nil, err
		}
	}

	masterPubKey, err := w.MasterPubKey(account)
	if err != nil {
		return nil, err
	}
	return masterPubKey.String(), nil
}

// getStakeInfo gets a large amounts of information about the stake environment
// and a number of statistics about local staking in the wallet.
func getStakeInfo(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var chainClient *rpcclient.Client
	if n, ok := s.walletLoader.NetworkBackend(); ok {
		client, err := chain.RPCClientFromBackend(n)
		if err == nil {
			chainClient = client
		}
	}
	var sinfo *wallet.StakeInfoData
	var err error
	if chainClient != nil {
		sinfo, err = w.StakeInfoPrecise(chainClient)
	} else {
		sinfo, err = w.StakeInfo()
	}
	if err != nil {
		return nil, err
	}

	var proportionLive, proportionMissed float64
	if sinfo.PoolSize > 0 {
		proportionLive = float64(sinfo.Live) / float64(sinfo.PoolSize)
	}
	if sinfo.Missed > 0 {
		proportionMissed = float64(sinfo.Missed) / (float64(sinfo.Voted + sinfo.Missed))
	}

	resp := &dosjson.GetStakeInfoResult{
		BlockHeight:  sinfo.BlockHeight,
		Difficulty:   sinfo.Sdiff.ToCoin(),
		TotalSubsidy: sinfo.TotalSubsidy.ToCoin(),

		OwnMempoolTix:  sinfo.OwnMempoolTix,
		Immature:       sinfo.Immature,
		Unspent:        sinfo.Unspent,
		Voted:          sinfo.Voted,
		Revoked:        sinfo.Revoked,
		UnspentExpired: sinfo.UnspentExpired,

		PoolSize:         sinfo.PoolSize,
		AllMempoolTix:    sinfo.AllMempoolTix,
		Live:             sinfo.Live,
		ProportionLive:   proportionLive,
		Missed:           sinfo.Missed,
		ProportionMissed: proportionMissed,
		Expired:          sinfo.Expired,
	}

	return resp, nil
}

// getTransaction handles a gettransaction request by returning details about
// a single transaction saved by wallet.
func getTransaction(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.GetTransactionCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	txHash, err := chainhash.NewHashFromStr(cmd.Txid)
	if err != nil {
		return nil, rpcError(dosjson.ErrRPCDecodeHexString, err)
	}

	// returns nil details when not found
	txd, err := wallet.UnstableAPI(w).TxDetails(txHash)
	if errors.Is(errors.NotExist, err) {
		return nil, rpcErrorf(dosjson.ErrRPCNoTxInfo, "no information for transaction")
	} else if err != nil {
		return nil, err
	}

	_, tipHeight := w.MainChainTip()

	var b strings.Builder
	b.Grow(2 * txd.MsgTx.SerializeSize())
	err = txd.MsgTx.Serialize(hex.NewEncoder(&b))
	if err != nil {
		return nil, err
	}

	// TODO: Add a "generated" field to this result type.  "generated":true
	// is only added if the transaction is a coinbase.
	ret := dosjson.GetTransactionResult{
		TxID:            cmd.Txid,
		Hex:             b.String(),
		Time:            txd.Received.Unix(),
		TimeReceived:    txd.Received.Unix(),
		WalletConflicts: []string{}, // Not saved
		//Generated:     blockchain.IsCoinBaseTx(&details.MsgTx),
	}

	if txd.Block.Height != -1 {
		ret.BlockHash = txd.Block.Hash.String()
		ret.BlockTime = txd.Block.Time.Unix()
		ret.Confirmations = int64(confirms(txd.Block.Height,
			tipHeight))
	}

	var (
		debitTotal  dosutil.Amount
		creditTotal dosutil.Amount
		fee         dosutil.Amount
		negFeeF64   float64
	)
	for _, deb := range txd.Debits {
		debitTotal += deb.Amount
	}
	for _, cred := range txd.Credits {
		creditTotal += cred.Amount
	}
	// Fee can only be determined if every input is a debit.
	if len(txd.Debits) == len(txd.MsgTx.TxIn) {
		var outputTotal dosutil.Amount
		for _, output := range txd.MsgTx.TxOut {
			outputTotal += dosutil.Amount(output.Value)
		}
		fee = debitTotal - outputTotal
		negFeeF64 = (-fee).ToCoin()
	}
	ret.Amount = (creditTotal - debitTotal).ToCoin()
	ret.Fee = negFeeF64

	details, err := w.ListTransactionDetails(txHash)
	if err != nil {
		return nil, err
	}
	ret.Details = make([]dosjson.GetTransactionDetailsResult, len(details))
	for i, d := range details {
		ret.Details[i] = dosjson.GetTransactionDetailsResult{
			Account:           d.Account,
			Address:           d.Address,
			Amount:            d.Amount,
			Category:          d.Category,
			InvolvesWatchOnly: d.InvolvesWatchOnly,
			Fee:               d.Fee,
			Vout:              d.Vout,
		}
	}

	return ret, nil
}

// getWalletFee returns the currently set tx fee for the requested wallet
func getWalletFee(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	return w.RelayFee().ToCoin(), nil
}

// These generators create the following global variables in this package:
//
//   var localeHelpDescs map[string]func() map[string]string
//   var requestUsages string
//
// localeHelpDescs maps from locale strings (e.g. "en_US") to a function that
// builds a map of help texts for each RPC server method.  This prevents help
// text maps for every locale map from being rooted and created during init.
// Instead, the appropiate function is looked up when help text is first needed
// using the current locale and saved to the global below for futher reuse.
//
// requestUsages contains single line usages for every supported request,
// separated by newlines.  It is set during init.  These usages are used for all
// locales.
//
//go:generate go run ../../internal/rpchelp/genrpcserverhelp.go legacyrpc
//go:generate gofmt -w rpcserverhelp.go

var helpDescs map[string]string
var helpDescsMu sync.Mutex // Help may execute concurrently, so synchronize access.

// help handles the help request by returning one line usage of all available
// methods, or full help for a specific method.  The chainClient is optional,
// and this is simply a helper function for the HelpNoChainRPC and
// HelpWithChainRPC handlers.
func help(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.HelpCmd)
	// TODO: The "help" RPC should use a HTTP POST client when calling down to
	// dcrd for additional help methods.  This avoids including websocket-only
	// requests in the help, which are not callable by wallet JSON-RPC clients.
	var chainClient *rpcclient.Client
	n, _ := s.walletLoader.NetworkBackend()
	if c, err := chain.RPCClientFromBackend(n); err == nil {
		chainClient = c
	}
	if cmd.Command == nil || *cmd.Command == "" {
		// Prepend chain server usage if it is available.
		usages := requestUsages
		if chainClient != nil {
			rawChainUsage, err := chainClient.RawRequest("help", nil)
			var chainUsage string
			if err == nil {
				_ = json.Unmarshal([]byte(rawChainUsage), &chainUsage)
			}
			if chainUsage != "" {
				usages = "Chain server usage:\n\n" + chainUsage + "\n\n" +
					"Wallet server usage (overrides chain requests):\n\n" +
					requestUsages
			}
		}
		return usages, nil
	}

	defer helpDescsMu.Unlock()
	helpDescsMu.Lock()

	if helpDescs == nil {
		// TODO: Allow other locales to be set via config or detemine
		// this from environment variables.  For now, hardcode US
		// English.
		helpDescs = localeHelpDescs["en_US"]()
	}

	helpText, ok := helpDescs[*cmd.Command]
	if ok {
		return helpText, nil
	}

	// Return the chain server's detailed help if possible.
	var chainHelp string
	if chainClient != nil {
		param := make([]byte, len(*cmd.Command)+2)
		param[0] = '"'
		copy(param[1:], *cmd.Command)
		param[len(param)-1] = '"'
		rawChainHelp, err := chainClient.RawRequest("help", []json.RawMessage{param})
		if err == nil {
			_ = json.Unmarshal([]byte(rawChainHelp), &chainHelp)
		}
	}
	if chainHelp != "" {
		return chainHelp, nil
	}
	return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "no help for method %q", *cmd.Command)
}

// listAccounts handles a listaccounts request by returning a map of account
// names to their balances.
func listAccounts(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ListAccountsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	accountBalances := map[string]float64{}
	results, err := w.CalculateAccountBalances(int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}
	for _, result := range results {
		accountName, err := w.AccountName(result.Account)
		if err != nil {
			// Expect name lookup to succeed
			if errors.Is(errors.NotExist, err) {
				return nil, rpcError(dosjson.ErrRPCInternal.Code, err)
			}
			return nil, err
		}
		accountBalances[accountName] = result.Spendable.ToCoin()
	}
	// Return the map.  This will be marshaled into a JSON object.
	return accountBalances, nil
}

// listLockUnspent handles a listlockunspent request by returning an slice of
// all locked outpoints.
func listLockUnspent(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	return w.LockedOutpoints(), nil
}

// listReceivedByAccount handles a listreceivedbyaccount request by returning
// a slice of objects, each one containing:
//  "account": the receiving account;
//  "amount": total amount received by the account;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.
func listReceivedByAccount(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ListReceivedByAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	results, err := w.TotalReceivedForAccounts(int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}

	jsonResults := make([]dosjson.ListReceivedByAccountResult, 0, len(results))
	for _, result := range results {
		jsonResults = append(jsonResults, dosjson.ListReceivedByAccountResult{
			Account:       result.AccountName,
			Amount:        result.TotalReceived.ToCoin(),
			Confirmations: uint64(result.LastConfirmation),
		})
	}
	return jsonResults, nil
}

// listReceivedByAddress handles a listreceivedbyaddress request by returning
// a slice of objects, each one containing:
//  "account": the account of the receiving address;
//  "address": the receiving address;
//  "amount": total amount received by the address;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.
func listReceivedByAddress(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ListReceivedByAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Intermediate data for each address.
	type AddrData struct {
		// Total amount received.
		amount dosutil.Amount
		// Number of confirmations of the last transaction.
		confirmations int32
		// Hashes of transactions which include an output paying to the address
		tx []string
	}

	_, tipHeight := w.MainChainTip()

	// Intermediate data for all addresses.
	allAddrData := make(map[string]AddrData)
	// Create an AddrData entry for each active address in the account.
	// Otherwise we'll just get addresses from transactions later.
	sortedAddrs, err := w.SortedActivePaymentAddresses()
	if err != nil {
		return nil, err
	}
	for _, address := range sortedAddrs {
		// There might be duplicates, just overwrite them.
		allAddrData[address] = AddrData{}
	}

	minConf := *cmd.MinConf
	var endHeight int32
	if minConf == 0 {
		endHeight = -1
	} else {
		endHeight = tipHeight - int32(minConf) + 1
	}
	err = wallet.UnstableAPI(w).RangeTransactions(0, endHeight, func(details []udb.TxDetails) (bool, error) {
		confirmations := confirms(details[0].Block.Height, tipHeight)
		for _, tx := range details {
			for _, cred := range tx.Credits {
				pkVersion := tx.MsgTx.TxOut[cred.Index].Version
				pkScript := tx.MsgTx.TxOut[cred.Index].PkScript
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkVersion,
					pkScript, w.ChainParams())
				if err != nil {
					// Non standard script, skip.
					continue
				}
				for _, addr := range addrs {
					addrStr := addr.EncodeAddress()
					addrData, ok := allAddrData[addrStr]
					if ok {
						addrData.amount += cred.Amount
						// Always overwrite confirmations with newer ones.
						addrData.confirmations = confirmations
					} else {
						addrData = AddrData{
							amount:        cred.Amount,
							confirmations: confirmations,
						}
					}
					addrData.tx = append(addrData.tx, tx.Hash.String())
					allAddrData[addrStr] = addrData
				}
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	// Massage address data into output format.
	numAddresses := len(allAddrData)
	ret := make([]dosjson.ListReceivedByAddressResult, numAddresses)
	idx := 0
	for address, addrData := range allAddrData {
		ret[idx] = dosjson.ListReceivedByAddressResult{
			Address:       address,
			Amount:        addrData.amount.ToCoin(),
			Confirmations: uint64(addrData.confirmations),
			TxIDs:         addrData.tx,
		}
		idx++
	}
	return ret, nil
}

// listSinceBlock handles a listsinceblock request by returning an array of maps
// with details of sent and received wallet transactions since the given block.
func listSinceBlock(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ListSinceBlockCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	tipHash, tipHeight := w.MainChainTip()
	targetConf := int32(*cmd.TargetConfirmations)
	if targetConf < 1 {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "target_confirmations must be positive")
	}

	// TODO: This must begin at the fork point in the main chain, not the height
	// of this block.
	var start int32
	if cmd.BlockHash != nil {
		hash, err := chainhash.NewHashFromStr(*cmd.BlockHash)
		if err != nil {
			return nil, rpcError(dosjson.ErrRPCDecodeHexString, err)
		}
		header, err := w.BlockHeader(hash)
		if err != nil {
			return nil, err
		}
		start = int32(header.Height)
	}

	txInfoList, err := w.ListSinceBlock(start, tipHeight+1-targetConf, tipHeight)
	if err != nil {
		return nil, err
	}

	res := &dosjson.ListSinceBlockResult{
		Transactions: txInfoList,
		LastBlock:    tipHash.String(),
	}
	return res, nil
}

// listScripts handles a listscripts request by returning an
// array of script details for all scripts in the wallet.
func listScripts(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	redeemScripts, err := w.FetchAllRedeemScripts()
	if err != nil {
		return nil, err
	}
	listScriptsResultSIs := make([]dosjson.ScriptInfo, len(redeemScripts))
	for i, redeemScript := range redeemScripts {
		p2shAddr, err := dosutil.NewAddressScriptHash(redeemScript,
			w.ChainParams())
		if err != nil {
			return nil, err
		}
		listScriptsResultSIs[i] = dosjson.ScriptInfo{
			Hash160:      hex.EncodeToString(p2shAddr.Hash160()[:]),
			Address:      p2shAddr.EncodeAddress(),
			RedeemScript: hex.EncodeToString(redeemScript),
		}
	}
	return &dosjson.ListScriptsResult{Scripts: listScriptsResultSIs}, nil
}

// listTransactions handles a listtransactions request by returning an
// array of maps with details of sent and recevied wallet transactions.
func listTransactions(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ListTransactionsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// TODO: ListTransactions does not currently understand the difference
	// between transactions pertaining to one account from another.  This
	// will be resolved when wtxmgr is combined with the waddrmgr namespace.

	if cmd.Account != nil && *cmd.Account != "*" {
		// For now, don't bother trying to continue if the user
		// specified an account, since this can't be (easily or
		// efficiently) calculated.
		return nil,
			errors.E(`Transactions can not be searched by account. ` +
				`Use "*" to reference all accounts.`)
	}

	return w.ListTransactions(*cmd.From, *cmd.Count)
}

// listAddressTransactions handles a listaddresstransactions request by
// returning an array of maps with details of spent and received wallet
// transactions.  The form of the reply is identical to listtransactions,
// but the array elements are limited to transaction details which are
// about the addresess included in the request.
func listAddressTransactions(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ListAddressTransactionsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter,
			"listing transactions for addresses may only be done for all accounts")
	}

	// Decode addresses.
	hash160Map := make(map[string]struct{})
	for _, addrStr := range cmd.Addresses {
		addr, err := decodeAddress(addrStr, w.ChainParams())
		if err != nil {
			return nil, err
		}
		hash160Map[string(addr.ScriptAddress())] = struct{}{}
	}

	return w.ListAddressTransactions(hash160Map)
}

// listAllTransactions handles a listalltransactions request by returning
// a map with details of sent and recevied wallet transactions.  This is
// similar to ListTransactions, except it takes only a single optional
// argument for the account name and replies with all transactions.
func listAllTransactions(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ListAllTransactionsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter,
			"listing all transactions may only be done for all accounts")
	}

	return w.ListAllTransactions()
}

// listUnspent handles the listunspent command.
func listUnspent(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ListUnspentCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	var addresses map[string]struct{}
	if cmd.Addresses != nil {
		addresses = make(map[string]struct{})
		// confirm that all of them are good:
		for _, as := range *cmd.Addresses {
			a, err := decodeAddress(as, w.ChainParams())
			if err != nil {
				return nil, err
			}
			addresses[a.EncodeAddress()] = struct{}{}
		}
	}

	result, err := w.ListUnspent(int32(*cmd.MinConf), int32(*cmd.MaxConf), addresses)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAddressNotInWallet
		}
		return nil, err
	}
	return result, nil
}

// lockUnspent handles the lockunspent command.
func lockUnspent(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.LockUnspentCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	switch {
	case cmd.Unlock && len(cmd.Transactions) == 0:
		w.ResetLockedOutpoints()
	default:
		for _, input := range cmd.Transactions {
			txSha, err := chainhash.NewHashFromStr(input.Txid)
			if err != nil {
				return nil, rpcError(dosjson.ErrRPCDecodeHexString, err)
			}
			op := wire.OutPoint{Hash: *txSha, Index: input.Vout}
			if cmd.Unlock {
				w.UnlockOutpoint(op)
			} else {
				w.LockOutpoint(op)
			}
		}
	}
	return true, nil
}

// makeOutputs creates a slice of transaction outputs from a pair of address
// strings to amounts.  This is used to create the outputs to include in newly
// created transactions from a JSON object describing the output destinations
// and amounts.
func makeOutputs(pairs map[string]dosutil.Amount, chainParams *chaincfg.Params) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0, len(pairs))
	for addrStr, amt := range pairs {
		if amt < 0 {
			return nil, errNeedPositiveAmount
		}
		addr, err := decodeAddress(addrStr, chainParams)
		if err != nil {
			return nil, err
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, wire.NewTxOut(int64(amt), pkScript))
	}
	return outputs, nil
}

// makeCreateOutputs create a create contract transaction output.
func makeCreateOutputs(address string, bin string, abi string, chainParams *chaincfg.Params, noPayGas bool) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0, 1)
	addr, err := decodeAddress(address, chainParams)
	if err != nil {
		return nil, err
	}

	binCode, err := hex.DecodeString(bin)
	if err != nil {
		return nil, err
	}

	script, err := txscript.PayToStxCreatePubKeyHash(addr.ScriptAddress(), binCode, []byte(abi), noPayGas)
	if err != nil {
		return nil, err
	}

	outputs = append(outputs, wire.NewTxOut(0, script))
	return outputs, nil
}

// makeCallOutputs  create a call contract transaction output.
func makeCallOutputs(address string, code []byte, chainParams *chaincfg.Params) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0, 1)
	addr, err := decodeAddress(address, chainParams)
	if err != nil {
		return nil, err
	}

	script, err := txscript.PayToStxCallPubKeyHash(addr.ScriptAddress(), code)
	if err != nil {
		return nil, err
	}

	outputs = append(outputs, wire.NewTxOut(0, script))
	return outputs, nil
}

// sendPairs creates and sends payment transactions.
// It returns the transaction hash in string format upon success
// All errors are returned in dosjson.RPCError format
func sendPairs(w *wallet.Wallet, amounts map[string]dosutil.Amount, account uint32, minconf int32) (string, error) {
	outputs, err := makeOutputs(amounts, w.ChainParams())
	if err != nil {
		return "", err
	}
	txSha, err := w.SendOutputs(outputs, account, minconf)
	if err != nil {
		if errors.Is(errors.Locked, err) {
			return "", errWalletUnlockNeeded
		}
		if errors.Is(errors.InsufficientBalance, err) {
			return "", rpcError(dosjson.ErrRPCWalletInsufficientFunds, err)
		}
		return "", err
	}

	return txSha.String(), nil
}

// sendPairs creates and sends payment transactions.
// It returns the transaction hash in string format upon success
// All errors are returned in dosjson.RPCError format
func sendPairsV2(w *wallet.Wallet, outputs []*wire.TxOut, account uint32, inputSource txauthor.InputSource, changeSource txauthor.ChangeSource) (string, error) {
	txSha, err := w.SendOutputsUnspents(outputs, account, inputSource, changeSource)
	if err != nil {
		if errors.Is(errors.Locked, err) {
			return "", errWalletUnlockNeeded
		}
		if errors.Is(errors.InsufficientBalance, err) {
			return "", rpcError(dosjson.ErrRPCWalletInsufficientFunds, err)
		}
		return "", err
	}

	return txSha.String(), nil
}

// redeemMultiSigOut receives a transaction hash/idx and fetches the first output
// index or indices with known script hashes from the transaction. It then
// construct a transaction with a single P2PKH paying to a specified address.
// It signs any inputs that it can, then provides the raw transaction to
// the user to export to others to sign.
func redeemMultiSigOut(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.RedeemMultiSigOutCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Convert the address to a useable format. If
	// we have no address, create a new address in
	// this wallet to send the output to.
	var addr dosutil.Address
	var err error
	if cmd.Address != nil {
		addr, err = decodeAddress(*cmd.Address, w.ChainParams())
		if err != nil {
			return nil, err
		}
	} else {
		account := uint32(udb.DefaultAccountNum)
		addr, err = w.NewInternalAddress(account, wallet.WithGapPolicyWrap())
		if err != nil {
			return nil, err
		}
	}

	// Lookup the multisignature output and get the amount
	// along with the script for that transaction. Then,
	// begin crafting a MsgTx.
	hash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, rpcError(dosjson.ErrRPCInvalidParameter, err)
	}
	op := wire.OutPoint{
		Hash:  *hash,
		Index: cmd.Index,
		Tree:  cmd.Tree,
	}
	p2shOutput, err := w.FetchP2SHMultiSigOutput(&op)
	if err != nil {
		return nil, err
	}
	sc := txscript.GetScriptClass(txscript.DefaultScriptVersion,
		p2shOutput.RedeemScript)
	if sc != txscript.MultiSigTy {
		return nil, errors.E("P2SH redeem script is not multisig")
	}
	var msgTx wire.MsgTx
	txIn := wire.NewTxIn(&op, int64(p2shOutput.OutputAmount), nil)
	msgTx.AddTxIn(txIn)

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}

	err = w.PrepareRedeemMultiSigOutTxOutput(&msgTx, p2shOutput, &pkScript)
	if err != nil {
		return nil, err
	}

	// Start creating the SignRawTransactionCmd.
	outpointScript, err := txscript.PayToScriptHashScript(p2shOutput.P2SHAddress.Hash160()[:])
	if err != nil {
		return nil, err
	}
	outpointScriptStr := hex.EncodeToString(outpointScript)

	rti := dosjson.RawTxInput{
		Txid:         cmd.Hash,
		Vout:         cmd.Index,
		Tree:         cmd.Tree,
		ScriptPubKey: outpointScriptStr,
		RedeemScript: "",
	}
	rtis := []dosjson.RawTxInput{rti}

	var b strings.Builder
	b.Grow(2 * msgTx.SerializeSize())
	err = msgTx.Serialize(hex.NewEncoder(&b))
	if err != nil {
		return nil, err
	}
	sigHashAll := "ALL"

	srtc := &dosjson.SignRawTransactionCmd{
		RawTx:    b.String(),
		Inputs:   &rtis,
		PrivKeys: &[]string{},
		Flags:    &sigHashAll,
	}

	// Sign it and give the results to the user.
	signedTxResult, err := signRawTransaction(s, srtc)
	if signedTxResult == nil || err != nil {
		return nil, err
	}
	srtTyped := signedTxResult.(dosjson.SignRawTransactionResult)
	return dosjson.RedeemMultiSigOutResult(srtTyped), nil
}

// redeemMultisigOuts receives a script hash (in the form of a
// script hash address), looks up all the unspent outpoints associated
// with that address, then generates a list of partially signed
// transactions spending to either an address specified or internal
// addresses in this wallet.
func redeemMultiSigOuts(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.RedeemMultiSigOutsCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Get all the multisignature outpoints that are unspent for this
	// address.
	addr, err := decodeAddress(cmd.FromScrAddress, w.ChainParams())
	if err != nil {
		return nil, err
	}
	p2shAddr, ok := addr.(*dosutil.AddressScriptHash)
	if !ok {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "address is not P2SH")
	}
	msos, err := wallet.UnstableAPI(w).UnspentMultisigCreditsForAddress(p2shAddr)
	if err != nil {
		return nil, err
	}
	max := uint32(0xffffffff)
	if cmd.Number != nil {
		max = uint32(*cmd.Number)
	}

	itr := uint32(0)
	rmsoResults := make([]dosjson.RedeemMultiSigOutResult, len(msos))
	for i, mso := range msos {
		if itr > max {
			break
		}

		rmsoRequest := &dosjson.RedeemMultiSigOutCmd{
			Hash:    mso.OutPoint.Hash.String(),
			Index:   mso.OutPoint.Index,
			Tree:    mso.OutPoint.Tree,
			Address: cmd.ToAddress,
		}
		redeemResult, err := redeemMultiSigOut(s, rmsoRequest)
		if err != nil {
			return nil, err
		}
		redeemResultTyped := redeemResult.(dosjson.RedeemMultiSigOutResult)
		rmsoResults[i] = redeemResultTyped

		itr++
	}

	return dosjson.RedeemMultiSigOutsResult{Results: rmsoResults}, nil
}

// rescanWallet initiates a rescan of the block chain for wallet data, blocking
// until the rescan completes or exits with an error.
func rescanWallet(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.RescanWalletCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	n, ok := s.walletLoader.NetworkBackend()
	if !ok {
		return nil, errNoNetwork
	}

	err := w.RescanFromHeight(context.TODO(), n, int32(*cmd.BeginHeight))
	return nil, err
}

func isNilOrEmpty(s *string) bool {
	return s == nil || *s == ""
}

// sendFrom handles a sendfrom RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func sendFrom(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.SendFromCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, rpcErrorf(dosjson.ErrRPCUnimplemented, "transaction comments are unsupported")
	}

	account, err := w.AccountNumber(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that signed integer parameters are positive.
	if cmd.Amount < 0 {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "negative amount")
	}
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "negative minconf")
	}
	// Create map of address and amount pairs.
	amt, err := dosutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, rpcError(dosjson.ErrRPCInvalidParameter, err)
	}
	pairs := map[string]dosutil.Amount{
		cmd.ToAddress: amt,
	}

	return sendPairs(w, pairs, account, minConf)
}

// sendMany handles a sendmany RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to any number of
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.
func sendMany(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.SendManyCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) {
		return nil, rpcErrorf(dosjson.ErrRPCUnimplemented, "transaction comments are unsupported")
	}

	account, err := w.AccountNumber(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that minconf is positive.
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "negative minconf")
	}

	// Recreate address/amount pairs, using dosutil.Amount.
	pairs := make(map[string]dosutil.Amount, len(cmd.Amounts))
	for k, v := range cmd.Amounts {
		amt, err := dosutil.NewAmount(v)
		if err != nil {
			return nil, rpcError(dosjson.ErrRPCInvalidParameter, err)
		}
		pairs[k] = amt
	}

	return sendPairs(w, pairs, account, minConf)
}

// sendToAddress handles a sendtoaddress RPC request by creating a new
// transaction spending unspent transaction outputs for a wallet to another
// payment address.  Leftover inputs not sent to the payment address or a fee
// for the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func sendToAddress(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.SendToAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, rpcErrorf(dosjson.ErrRPCUnimplemented, "transaction comments are unsupported")
	}

	amt, err := dosutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}

	// Check that signed integer parameters are positive.
	if amt < 0 {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "negative amount")
	}

	// Mock up map of address and amount pairs.
	pairs := map[string]dosutil.Amount{
		cmd.Address: amt,
	}

	// sendtoaddress always spends from the default account, this matches bitcoind
	return sendPairs(w, pairs, udb.DefaultAccountNum, 1)
}

// sendToMultiSig handles a sendtomultisig RPC request by creating a new
// transaction spending amount many funds to an output containing a multi-
// signature script hash. The function will fail if there isn't at least one
// public key in the public key list that corresponds to one that is owned
// locally.
// Upon successfully sending the transaction to the daemon, the script hash
// is stored in the transaction manager and the corresponding address
// specified to be watched by the daemon.
// The function returns a tx hash, P2SH address, and a multisig script if
// successful.
// TODO Use with non-default accounts as well
func sendToMultiSig(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.SendToMultiSigCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	account := uint32(udb.DefaultAccountNum)
	amount, err := dosutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, rpcError(dosjson.ErrRPCInvalidParameter, err)
	}
	nrequired := int8(*cmd.NRequired)
	minconf := int32(*cmd.MinConf)
	pubkeys := make([]*dosutil.AddressSecpPubKey, len(cmd.Pubkeys))

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, a := range cmd.Pubkeys {
		// Try to parse as pubkey address.
		a, err := decodeAddress(a, w.ChainParams())
		if err != nil {
			return nil, err
		}

		switch addr := a.(type) {
		case *dosutil.AddressSecpPubKey:
			pubkeys[i] = addr
		default:
			pubKey, err := w.PubKeyForAddress(addr)
			if err != nil {
				if errors.Is(errors.NotExist, err) {
					return nil, errAddressNotInWallet
				}
				return nil, err
			}
			if dosec.SignatureType(pubKey.GetType()) != dosec.STEcdsaSecp256k1 {
				return nil, errors.New("only secp256k1 " +
					"pubkeys are currently supported")
			}
			pubKeyAddr, err := dosutil.NewAddressSecpPubKey(
				pubKey.Serialize(), w.ChainParams())
			if err != nil {
				return nil, err
			}
			pubkeys[i] = pubKeyAddr
		}
	}

	ctx, addr, script, err :=
		w.CreateMultisigTx(account, amount, pubkeys, nrequired, minconf)
	if err != nil {
		return nil, err
	}

	result := &dosjson.SendToMultiSigResult{
		TxHash:       ctx.MsgTx.TxHash().String(),
		Address:      addr.EncodeAddress(),
		RedeemScript: hex.EncodeToString(script),
	}

	log.Infof("Successfully sent funds to multisignature output in "+
		"transaction %v", ctx.MsgTx.TxHash().String())

	return result, nil
}

// transfer handles a transfer RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func transfer(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.TransferCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, rpcErrorf(dosjson.ErrRPCUnimplemented, "transaction comments are unsupported")
	}

	account, err := w.AccountNumber(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that signed integer parameters are positive.
	if cmd.Amount < 0 {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "negative amount")
	}
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "negative minconf")
	}
	// Create map of address and amount pairs.
	amt, err := dosutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, rpcError(dosjson.ErrRPCInvalidParameter, err)
	}
	pairs, err := makeOutputs(map[string]dosutil.Amount{
		cmd.ToAddress: amt,
	}, s.activeNet)
	if err != nil {
		return nil, err
	}

	source := &defaultAddressChangeSource{
		account: account,
		branch:  udb.ExternalBranch,
		wallet:  w,
	}

	return sendPairsV2(w, pairs, account, nil, source)
}

// setTxFee sets the transaction fee per kilobyte added to transactions.
func setTxFee(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.SetTxFeeCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// Check that amount is not negative.
	if cmd.Amount < 0 {
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "negative amount")
	}

	relayFee, err := dosutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, rpcError(dosjson.ErrRPCInvalidParameter, err)
	}
	w.SetRelayFee(relayFee)

	// A boolean true result is returned upon success.
	return true, nil
}

// signMessage signs the given message with the private key for the given
// address
func signMessage(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.SignMessageCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}
	sig, err := w.SignMessage(cmd.Message, addr)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAddressNotInWallet
		}
		if errors.Is(errors.Locked, err) {
			return nil, errWalletUnlockNeeded
		}
		return nil, err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// signRawTransaction handles the signrawtransaction command.
//
// chainClient may be nil, in which case it was called by the NoChainRPC
// variant.  It must be checked before all usage.
func signRawTransaction(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.SignRawTransactionCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	tx := wire.NewMsgTx()
	err := tx.Deserialize(hex.NewDecoder(strings.NewReader(cmd.RawTx)))
	if err != nil {
		return nil, rpcError(dosjson.ErrRPCDeserialization, err)
	}

	var hashType txscript.SigHashType
	switch *cmd.Flags {
	case "ALL":
		hashType = txscript.SigHashAll
	case "NONE":
		hashType = txscript.SigHashNone
	case "SINGLE":
		hashType = txscript.SigHashSingle
	case "ALL|ANYONECANPAY":
		hashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	case "NONE|ANYONECANPAY":
		hashType = txscript.SigHashNone | txscript.SigHashAnyOneCanPay
	case "SINGLE|ANYONECANPAY":
		hashType = txscript.SigHashSingle | txscript.SigHashAnyOneCanPay
	case "ssgen": // Special case of SigHashAll
		hashType = txscript.SigHashAll
	case "ssrtx": // Special case of SigHashAll
		hashType = txscript.SigHashAll
	default:
		return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "invalid sighash flag")
	}

	// TODO: really we probably should look these up with dcrd anyway to
	// make sure that they match the blockchain if present.
	inputs := make(map[wire.OutPoint][]byte)
	scripts := make(map[string][]byte)
	var cmdInputs []dosjson.RawTxInput
	if cmd.Inputs != nil {
		cmdInputs = *cmd.Inputs
	}
	for _, rti := range cmdInputs {
		inputSha, err := chainhash.NewHashFromStr(rti.Txid)
		if err != nil {
			return nil, rpcError(dosjson.ErrRPCInvalidParameter, err)
		}

		script, err := decodeHexStr(rti.ScriptPubKey)
		if err != nil {
			return nil, err
		}

		// redeemScript is only actually used iff the user provided
		// private keys. In which case, it is used to get the scripts
		// for signing. If the user did not provide keys then we always
		// get scripts from the wallet.
		// Empty strings are ok for this one and hex.DecodeString will
		// DTRT.
		// Note that redeemScript is NOT only the redeemscript
		// required to be appended to the end of a P2SH output
		// spend, but the entire signature script for spending
		// *any* outpoint with dummy values inserted into it
		// that can later be replacing by txscript's sign.
		if cmd.PrivKeys != nil && len(*cmd.PrivKeys) != 0 {
			redeemScript, err := decodeHexStr(rti.RedeemScript)
			if err != nil {
				return nil, err
			}

			addr, err := dosutil.NewAddressScriptHash(redeemScript,
				w.ChainParams())
			if err != nil {
				return nil, err
			}
			scripts[addr.String()] = redeemScript
		}
		inputs[wire.OutPoint{
			Hash:  *inputSha,
			Tree:  rti.Tree,
			Index: rti.Vout,
		}] = script
	}

	// Now we go and look for any inputs that we were not provided by
	// querying dcrd with getrawtransaction. We queue up a bunch of async
	// requests and will wait for replies after we have checked the rest of
	// the arguments.
	var requested map[wire.OutPoint]rpcclient.FutureGetTxOutResult
	n, _ := s.walletLoader.NetworkBackend()
	chainClient, err := chain.RPCClientFromBackend(n)
	if err == nil {
		requested = make(map[wire.OutPoint]rpcclient.FutureGetTxOutResult)
		for i, txIn := range tx.TxIn {
			// We don't need the first input of a stakebase tx, as it's garbage
			// anyway.
			if i == 0 && *cmd.Flags == "ssgen" {
				continue
			}

			// Did we get this outpoint from the arguments?
			if _, ok := inputs[txIn.PreviousOutPoint]; ok {
				continue
			}

			// Asynchronously request the output script.
			requested[txIn.PreviousOutPoint] = chainClient.GetTxOutAsync(
				&txIn.PreviousOutPoint.Hash, txIn.PreviousOutPoint.Index,
				true)
		}
	}

	// Parse list of private keys, if present. If there are any keys here
	// they are the keys that we may use for signing. If empty we will
	// use any keys known to us already.
	var keys map[string]*dosutil.WIF
	if cmd.PrivKeys != nil {
		keys = make(map[string]*dosutil.WIF)

		for _, key := range *cmd.PrivKeys {
			wif, err := dosutil.DecodeWIF(key)
			if err != nil {
				return nil, rpcError(dosjson.ErrRPCDeserialization, err)
			}

			if !wif.IsForNet(w.ChainParams()) {
				return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "key intended for different network")
			}

			var addr dosutil.Address
			switch wif.DSA() {
			case dosec.STEcdsaSecp256k1:
				addr, err = dosutil.NewAddressSecpPubKey(wif.SerializePubKey(),
					w.ChainParams())
				if err != nil {
					return nil, err
				}
			case dosec.STEd25519:
				addr, err = dosutil.NewAddressEdwardsPubKey(
					wif.SerializePubKey(),
					w.ChainParams())
				if err != nil {
					return nil, err
				}
			case dosec.STSchnorrSecp256k1:
				addr, err = dosutil.NewAddressSecSchnorrPubKey(
					wif.SerializePubKey(),
					w.ChainParams())
				if err != nil {
					return nil, err
				}
			}
			keys[addr.EncodeAddress()] = wif
		}
	}

	// We have checked the rest of the args. now we can collect the async
	// txs. TODO: If we don't mind the possibility of wasting work we could
	// move waiting to the following loop and be slightly more asynchronous.
	for outPoint, resp := range requested {
		result, err := resp.Receive()
		if err != nil {
			return nil, errors.E(errors.Op("dosd.jsonrpc.gettxout"), err)
		}
		// gettxout returns JSON null if the output is found, but is spent by
		// another transaction in the main chain.
		if result == nil {
			continue
		}
		script, err := hex.DecodeString(result.ScriptPubKey.Hex)
		if err != nil {
			return nil, rpcError(dosjson.ErrRPCDecodeHexString, err)
		}
		inputs[outPoint] = script
	}

	// All args collected. Now we can sign all the inputs that we can.
	// `complete' denotes that we successfully signed all outputs and that
	// all scripts will run to completion. This is returned as part of the
	// reply.
	signErrs, err := w.SignTransaction(tx, hashType, inputs, keys, scripts)
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	b.Grow(2 * tx.SerializeSize())
	err = tx.Serialize(hex.NewEncoder(&b))
	if err != nil {
		return nil, err
	}

	signErrors := make([]dosjson.SignRawTransactionError, 0, len(signErrs))
	for _, e := range signErrs {
		input := tx.TxIn[e.InputIndex]
		signErrors = append(signErrors, dosjson.SignRawTransactionError{
			TxID:      input.PreviousOutPoint.Hash.String(),
			Vout:      input.PreviousOutPoint.Index,
			ScriptSig: hex.EncodeToString(input.SignatureScript),
			Sequence:  input.Sequence,
			Error:     e.Error.Error(),
		})
	}

	return dosjson.SignRawTransactionResult{
		Hex:      b.String(),
		Complete: len(signErrors) == 0,
		Errors:   signErrors,
	}, nil
}

// signRawTransactions handles the signrawtransactions command.
func signRawTransactions(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.SignRawTransactionsCmd)

	// Sign each transaction sequentially and record the results.
	// Error out if we meet some unexpected failure.
	results := make([]dosjson.SignRawTransactionResult, len(cmd.RawTxs))
	for i, etx := range cmd.RawTxs {
		flagAll := "ALL"
		srtc := &dosjson.SignRawTransactionCmd{
			RawTx: etx,
			Flags: &flagAll,
		}
		result, err := signRawTransaction(s, srtc)
		if err != nil {
			return nil, err
		}

		tResult := result.(dosjson.SignRawTransactionResult)
		results[i] = tResult
	}

	// If the user wants completed transactions to be automatically send,
	// do that now. Otherwise, construct the slice and return it.
	toReturn := make([]dosjson.SignedTransaction, len(cmd.RawTxs))

	if *cmd.Send {
		n, ok := s.walletLoader.NetworkBackend()
		if !ok {
			return nil, errNoNetwork
		}

		for i, result := range results {
			if result.Complete {
				// Slow/mem hungry because of the deserializing.
				msgTx := wire.NewMsgTx()
				err := msgTx.Deserialize(hex.NewDecoder(strings.NewReader(result.Hex)))
				if err != nil {
					return nil, rpcError(dosjson.ErrRPCDeserialization, err)
				}
				sent := false
				hashStr := ""
				err = n.PublishTransactions(context.TODO(), msgTx)
				// If sendrawtransaction errors out (blockchain rule
				// issue, etc), continue onto the next transaction.
				if err == nil {
					sent = true
					hashStr = msgTx.TxHash().String()
				}

				st := dosjson.SignedTransaction{
					SigningResult: result,
					Sent:          sent,
					TxHash:        &hashStr,
				}
				toReturn[i] = st
			} else {
				st := dosjson.SignedTransaction{
					SigningResult: result,
					Sent:          false,
					TxHash:        nil,
				}
				toReturn[i] = st
			}
		}
	} else { // Just return the results.
		for i, result := range results {
			st := dosjson.SignedTransaction{
				SigningResult: result,
				Sent:          false,
				TxHash:        nil,
			}
			toReturn[i] = st
		}
	}

	return &dosjson.SignRawTransactionsResult{Results: toReturn}, nil
}

// scriptChangeSource is a ChangeSource which is used to
// receive all correlated previous input value.
type scriptChangeSource struct {
	version uint16
	script  []byte
}

func (src *scriptChangeSource) Script() ([]byte, uint16, error) {
	return src.script, src.version, nil
}

func (src *scriptChangeSource) ScriptSize() int {
	return len(src.script)
}

func makeScriptChangeSource(address string, version uint16) (*scriptChangeSource, error) {
	destinationAddress, err := dosutil.DecodeAddress(address)
	if err != nil {
		return nil, err
	}

	script, err := txscript.PayToAddrScript(destinationAddress)
	if err != nil {
		return nil, err
	}

	source := &scriptChangeSource{
		version: version,
		script:  script,
	}

	return source, nil
}

// sweepAccount handles the sweepaccount command.
func sweepAccount(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.SweepAccountCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	// use provided fee per Kb if specified
	feePerKb := w.RelayFee()
	if cmd.FeePerKb != nil {
		var err error
		feePerKb, err = dosutil.NewAmount(*cmd.FeePerKb)
		if err != nil {
			return nil, rpcError(dosjson.ErrRPCInvalidParameter, err)
		}
	}

	// use provided required confirmations if specified
	requiredConfs := int32(1)
	if cmd.RequiredConfirmations != nil {
		requiredConfs = int32(*cmd.RequiredConfirmations)
		if requiredConfs < 0 {
			return nil, errNeedPositiveAmount
		}
	}

	account, err := w.AccountNumber(cmd.SourceAccount)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			return nil, errAccountNotFound
		}
		return nil, err
	}

	changeSource, err := makeScriptChangeSource(cmd.DestinationAddress,
		txscript.DefaultScriptVersion)
	if err != nil {
		return nil, err
	}
	tx, err := w.NewUnsignedTransaction(nil, feePerKb, account,
		requiredConfs, wallet.OutputSelectionAlgorithmAll, changeSource)
	if err != nil {
		if errors.Is(errors.InsufficientBalance, err) {
			return nil, rpcError(dosjson.ErrRPCWalletInsufficientFunds, err)
		}
		return nil, err
	}

	var b strings.Builder
	b.Grow(2 * tx.Tx.SerializeSize())
	err = tx.Tx.Serialize(hex.NewEncoder(&b))
	if err != nil {
		return nil, err
	}

	res := &dosjson.SweepAccountResult{
		UnsignedTransaction:       b.String(),
		TotalPreviousOutputAmount: tx.TotalInput.ToCoin(),
		TotalOutputAmount:         helpers.SumOutputValues(tx.Tx.TxOut).ToCoin(),
		EstimatedSignedSize:       uint32(tx.EstimatedSignedSerializeSize),
	}

	return res, nil
}

// validateAddress handles the validateaddress command.
func validateAddress(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.ValidateAddressCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	result := dosjson.ValidateAddressWalletResult{}
	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		// Use result zero value (IsValid=false).
		return result, nil
	}

	// We could put whether or not the address is a script here,
	// by checking the type of "addr", however, the reference
	// implementation only puts that information if the script is
	// "ismine", and we follow that behaviour.
	result.Address = addr.EncodeAddress()
	result.IsValid = true

	ainfo, err := w.AddressInfo(addr)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			// No additional information available about the address.
			return result, nil
		}
		return nil, err
	}

	// The address lookup was successful which means there is further
	// information about it available and it is "mine".
	result.IsMine = true
	acctName, err := w.AccountName(ainfo.Account())
	if err != nil {
		return nil, err
	}
	result.Account = acctName

	switch ma := ainfo.(type) {
	case udb.ManagedPubKeyAddress:
		result.IsCompressed = ma.Compressed()
		result.PubKey = ma.ExportPubKey()
		pubKeyBytes, err := hex.DecodeString(result.PubKey)
		if err != nil {
			return nil, err
		}
		pubKeyAddr, err := dosutil.NewAddressSecpPubKey(pubKeyBytes,
			w.ChainParams())
		if err != nil {
			return nil, err
		}
		result.PubKeyAddr = pubKeyAddr.String()

	case udb.ManagedScriptAddress:
		result.IsScript = true

		// The script is only available if the manager is unlocked, so
		// just break out now if there is an error.
		script, err := w.RedeemScriptCopy(addr)
		if err != nil {
			if errors.Is(errors.Locked, err) {
				break
			}
			return nil, err
		}
		result.Hex = hex.EncodeToString(script)

		// This typically shouldn't fail unless an invalid script was
		// imported.  However, if it fails for any reason, there is no
		// further information available, so just set the script type
		// a non-standard and break out now.
		class, addrs, reqSigs, err := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, script, w.ChainParams())
		if err != nil {
			result.Script = txscript.NonStandardTy.String()
			break
		}

		addrStrings := make([]string, len(addrs))
		for i, a := range addrs {
			addrStrings[i] = a.EncodeAddress()
		}
		result.Addresses = addrStrings

		// Multi-signature scripts also provide the number of required
		// signatures.
		result.Script = class.String()
		if class == txscript.MultiSigTy {
			result.SigsRequired = int32(reqSigs)
		}
	}

	return result, nil
}

// verifyMessage handles the verifymessage command by verifying the provided
// compact signature for the given address and message.
func verifyMessage(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.VerifyMessageCmd)

	var valid bool

	// Decode address and base64 signature from the request.
	addr, err := dosutil.DecodeAddress(cmd.Address)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil {
		return nil, err
	}

	// Addresses must have an associated secp256k1 private key and therefore
	// must be P2PK or P2PKH (P2SH is not allowed).
	switch a := addr.(type) {
	case *dosutil.AddressSecpPubKey:
	case *dosutil.AddressPubKeyHash:
		if a.DSA(a.Net()) != dosec.STEcdsaSecp256k1 {
			goto WrongAddrKind
		}
	default:
		goto WrongAddrKind
	}

	valid, err = wallet.VerifyMessage(cmd.Message, addr, sig)
	// Mirror Bitcoin Core behavior, which treats all erorrs as an invalid
	// signature.
	return err == nil && valid, nil

WrongAddrKind:
	return nil, rpcErrorf(dosjson.ErrRPCInvalidParameter, "address must be secp256k1 P2PK or P2PKH")
}

// version handles the version command by returning the RPC API versions of the
// wallet and, optionally, the consensus RPC server as well if it is associated
// with the server.  The chainClient is optional, and this is simply a helper
// function for the versionWithChainRPC and versionNoChainRPC handlers.
func version(s *Server, icmd interface{}) (interface{}, error) {
	var resp map[string]dosjson.VersionResult
	n, _ := s.walletLoader.NetworkBackend()
	chainClient, err := chain.RPCClientFromBackend(n)
	if err == nil {
		var err error
		resp, err = chainClient.Version()
		if err != nil {
			return nil, err
		}
	} else {
		resp = make(map[string]dosjson.VersionResult)
	}

	resp["dcrwalletjsonrpcapi"] = dosjson.VersionResult{
		VersionString: jsonrpcSemverString,
		Major:         jsonrpcSemverMajor,
		Minor:         jsonrpcSemverMinor,
		Patch:         jsonrpcSemverPatch,
	}
	return resp, nil
}

// walletInfo gets the current information about the wallet. If the daemon
// is connected and fails to ping, the function will still return that the
// daemon is disconnected.
func walletInfo(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	n, err := w.NetworkBackend()
	connected := err == nil
	if connected {
		chainClient, err := chain.RPCClientFromBackend(n)
		if err == nil {
			err := chainClient.Ping()
			if err != nil {
				log.Warnf("Ping failed on connected daemon client: %v", err)
				connected = false
			}
		}
	}

	unlocked := !(w.Locked())
	fi := w.RelayFee()
	var voteVersion uint32

	return &dosjson.WalletInfoResult{
		DaemonConnected:  connected,
		Unlocked:         unlocked,
		TxFee:            fi.ToCoin(),
		TicketFee:        0,
		TicketPurchasing: false,
		VoteBits:         0,
		VoteBitsExtended: "",
		VoteVersion:      voteVersion,
		Voting:           false,
	}, nil
}

// walletIsLocked handles the walletislocked extension request by
// returning the current lock state (false for unlocked, true for locked)
// of an account.
func walletIsLocked(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	return w.Locked(), nil
}

// walletLock handles a walletlock request by locking the all account
// wallets, returning an error if any wallet is not encrypted (for example,
// a watching-only wallet).
func walletLock(s *Server, icmd interface{}) (interface{}, error) {
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	w.Lock()
	return nil, nil
}

// walletPassphrase responds to the walletpassphrase request by unlocking
// the wallet.  The decryption key is saved in the wallet until timeout
// seconds expires, after which the wallet is locked.
func walletPassphrase(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.WalletPassphraseCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	timeout := time.Second * time.Duration(cmd.Timeout)
	var unlockAfter <-chan time.Time
	if timeout != 0 {
		unlockAfter = time.After(timeout)
	}
	err := w.Unlock([]byte(cmd.Passphrase), unlockAfter)
	return nil, err
}

// walletPassphraseChange responds to the walletpassphrasechange request
// by unlocking all accounts with the provided old passphrase, and
// re-encrypting each private key with an AES key derived from the new
// passphrase.
//
// If the old passphrase is correct and the passphrase is changed, all
// wallets will be immediately locked.
func walletPassphraseChange(s *Server, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dosjson.WalletPassphraseChangeCmd)
	w, ok := s.walletLoader.LoadedWallet()
	if !ok {
		return nil, errUnloadedWallet
	}

	err := w.ChangePrivatePassphrase([]byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	if err != nil {
		if errors.Is(errors.Passphrase, err) {
			return nil, rpcErrorf(dosjson.ErrRPCWalletPassphraseIncorrect, "incorrect passphrase")
		}
		return nil, err
	}
	return nil, nil
}

// decodeHexStr decodes the hex encoding of a string, possibly prepending a
// leading '0' character if there is an odd number of bytes in the hex string.
// This is to prevent an error for an invalid hex string when using an odd
// number of bytes when calling hex.Decode.
func decodeHexStr(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, rpcErrorf(dosjson.ErrRPCDecodeHexString, "hex string decode failed: %v", err)
	}
	return decoded, nil
}

type defaultAddressChangeSource struct {
	account uint32
	branch  uint32
	wallet  *wallet.Wallet
}

func (src *defaultAddressChangeSource) Script() ([]byte, uint16, error) {
	changeAddress, err := src.wallet.AccountBranchAddressRange(src.account, src.branch, 0, 1)
	if err != nil {
		return nil, 0, err
	}
	script, err := txscript.PayToAddrScript(changeAddress[0])
	if err != nil {
		return nil, 0, err
	}
	return script, txscript.DefaultScriptVersion, nil
}

func (src *defaultAddressChangeSource) ScriptSize() int {
	return 1 + 1 + 1 + 20 + 1 + 1 // txsizes.P2PKHPkScriptSize
}
