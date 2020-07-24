module gogs.doschain.org/doschain/doswallet

require (
	github.com/boltdb/bolt v1.3.1
	github.com/golang/protobuf v1.3.2
	github.com/gorilla/websocket v1.4.1
	github.com/jessevdk/go-flags v0.0.0-20141203071132-1679536dcc89
	github.com/jrick/bitset v1.0.0
	github.com/jrick/logrotate v1.0.0
	gogs.doschain.org/doschain/dosd latest
	gogs.doschain.org/doschain/dosd/chaincfg/chainhash latest
	gogs.doschain.org/doschain/dosd/dosjson latest
	gogs.doschain.org/doschain/dosd/wire latest
	gogs.doschain.org/doschain/slog v1.0.0
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	google.golang.org/grpc v1.24.0
)

go 1.13
