package inteltdx

import "context"

// attest produces one quote over reportData through a configfs-tsm report
// directory made for this call alone: tsmReport checks provider and
// generation and removes the directory on every path, and quote bounds the
// wait by ctx.
func attest(ctx context.Context, reportData [reportDataSize]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return quote(ctx, reportData)
}
