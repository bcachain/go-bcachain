package pobc

import (
	"github.com/bcachain/go-bcachain/common"
	"github.com/bcachain/go-bcachain/consensus"
	"github.com/bcachain/go-bcachain/core/types"
	"github.com/bcachain/go-bcachain/rpc"
)

// API is struct of pobc status
type API struct {
	chain consensus.ChainReader
	pobc  *PoBC
}

// GetSnapshot try to parse snapshot status from header
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*Snapshot, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.pobc.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetSnapshotAtHash try to parse snapshot status from header for specific hash
func (api *API) GetSnapshotAtHash(hash common.Hash) (*Snapshot, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.pobc.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetSigners try to parse signers from header for specific block
func (api *API) GetSigners(number *rpc.BlockNumber) ([]common.Address, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.pobc.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

// GetSignersAtHash try to parse signers from header for specific hash
func (api *API) GetSignersAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.pobc.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

// Proposals try to proposal new signer for network
func (api *API) Proposals() map[common.Address]bool {
	api.pobc.lock.RLock()
	defer api.pobc.lock.RUnlock()

	proposals := make(map[common.Address]bool)
	for address, auth := range api.pobc.proposals {
		proposals[address] = auth
	}
	return proposals
}

// Propose try to proposal new signer for network
func (api *API) Propose(address common.Address, auth bool) {
	api.pobc.lock.Lock()
	defer api.pobc.lock.Unlock()

	api.pobc.proposals[address] = auth
}

// Discard try to discard signer for network
func (api *API) Discard(address common.Address) {
	api.pobc.lock.Lock()
	defer api.pobc.lock.Unlock()

	delete(api.pobc.proposals, address)
}
