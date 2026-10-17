package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage"
)

func commandGuardedExplanation() (guardops.ExplanationDeliverer, error) {
	if usesProxiedServer() || store == nil {
		return nil, fmt.Errorf("guard: initialized direct server storage required")
	}
	provider, ok := storage.UnwrapStore(store).(guardops.ExplanationProvider)
	if !ok {
		return nil, fmt.Errorf("guard: backend does not support linked explanation delivery")
	}
	return provider.GuardedExplanationDeliverer()
}
func init() {
	explain := &cobra.Command{Use: "explain", Short: "Deliver one explanation linked to an original applied audit", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		CheckReadonly("guard explain")
		var request guardops.ExplanationRequest
		if err := readGuardRequest(cmd, &request); err != nil {
			return err
		}
		role, err := commandGuardedExplanation()
		if err != nil {
			return outputJSONRaw(guardops.ExplanationResult{Protocol: guardops.ExplanationProtocol, OperationID: request.OperationID, RequestDigest: guardops.ExplanationDigest(request), Outcome: "refused", ErrorCode: guardops.CodeCapabilityUnavailable})
		}
		ctx, err := issueOpsContext(rootCtx)
		if err != nil {
			return outputJSONRaw(guardops.ExplanationResult{Protocol: guardops.ExplanationProtocol, OperationID: request.OperationID, RequestDigest: guardops.ExplanationDigest(request), Outcome: "refused", ErrorCode: guardops.CodeContextUnavailable})
		}
		result, _ := role.Explain(ctx, request)
		if result.Outcome == "applied" && !result.Replayed {
			commandDidWrite.Store(true)
			commandDidExplicitDoltCommit = true
		}
		return outputJSONRaw(result)
	}}
	lookup := &cobra.Command{Use: "lookup-explanation", Short: "Resolve original linked explanation delivery without another write", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		var request guardops.ExplanationLookupRequest
		if err := readGuardRequest(cmd, &request); err != nil {
			return err
		}
		role, err := commandGuardedExplanation()
		if err != nil {
			return outputJSONRaw(guardops.ExplanationResult{Protocol: guardops.ExplanationProtocol, OperationID: request.OperationID, RequestDigest: request.RequestDigest, Outcome: "unknown", ErrorCode: guardops.CodeCapabilityUnavailable})
		}
		result, _ := role.LookupExplanation(rootCtx, request)
		return outputJSONRaw(result)
	}}
	for _, command := range []*cobra.Command{explain, lookup} {
		command.Flags().String("request-json", "", "Request JSON file, or - for stdin")
		_ = command.MarkFlagRequired("request-json")
	}
	guardCmd.AddCommand(explain, lookup)
}
