// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2016-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

import (
	"fmt"

	"gogs.doschain.org/doschain/dosd/dosjson"
	"gogs.doschain.org/doschain/doswallet/errors"
)

func convertError(err error) *dosjson.RPCError {
	if err, ok := err.(*dosjson.RPCError); ok {
		return err
	}

	code := dosjson.ErrRPCWallet
	if err, ok := err.(*errors.Error); ok {
		switch err.Kind {
		case errors.Bug:
			code = dosjson.ErrRPCInternal.Code
		case errors.Encoding:
			code = dosjson.ErrRPCInvalidParameter
		case errors.Locked:
			code = dosjson.ErrRPCWalletUnlockNeeded
		case errors.Passphrase:
			code = dosjson.ErrRPCWalletPassphraseIncorrect
		case errors.NoPeers:
			code = dosjson.ErrRPCClientNotConnected
		case errors.InsufficientBalance:
			code = dosjson.ErrRPCWalletInsufficientFunds
		}
	}
	return &dosjson.RPCError{
		Code:    code,
		Message: err.Error(),
	}
}

func rpcError(code dosjson.RPCErrorCode, err error) *dosjson.RPCError {
	return &dosjson.RPCError{
		Code:    code,
		Message: err.Error(),
	}
}

func rpcErrorf(code dosjson.RPCErrorCode, format string, args ...interface{}) *dosjson.RPCError {
	return &dosjson.RPCError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// Errors variables that are defined once here to avoid duplication.
var (
	errUnloadedWallet = &dosjson.RPCError{
		Code:    dosjson.ErrRPCWallet,
		Message: "request requires a wallet but wallet has not loaded yet",
	}

	errRPCClientNotConnected = &dosjson.RPCError{
		Code:    dosjson.ErrRPCClientNotConnected,
		Message: "disconnected from consensus RPC",
	}

	errNoNetwork = &dosjson.RPCError{
		Code:    dosjson.ErrRPCClientNotConnected,
		Message: "disconnected from network",
	}

	errAccountNotFound = &dosjson.RPCError{
		Code:    dosjson.ErrRPCWalletInvalidAccountName,
		Message: "account not found",
	}

	errAddressNotInWallet = &dosjson.RPCError{
		Code:    dosjson.ErrRPCWallet,
		Message: "address not found in wallet",
	}

	errNotImportedAccount = &dosjson.RPCError{
		Code:    dosjson.ErrRPCWallet,
		Message: "imported addresses must belong to the imported account",
	}

	errNeedPositiveAmount = &dosjson.RPCError{
		Code:    dosjson.ErrRPCInvalidParameter,
		Message: "amount must be positive",
	}

	errWalletUnlockNeeded = &dosjson.RPCError{
		Code:    dosjson.ErrRPCWalletUnlockNeeded,
		Message: "enter the wallet passphrase with walletpassphrase first",
	}

	errReservedAccountName = &dosjson.RPCError{
		Code:    dosjson.ErrRPCInvalidParameter,
		Message: "account name is reserved by RPC server",
	}
)
