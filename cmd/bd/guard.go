package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage"
)

// This experimental role is an explicit local capability. It does not select
// the ordinary update path when a backend or expectation is unsupported.
var guardCmd = &cobra.Command{
	Use: "guard", GroupID: "issues", Short: "Experimental guarded native release capability",
}

func isGuardCommand(cmd *cobra.Command) bool {
	return cmd != nil && cmd.Parent() == guardCmd
}

func commandGuardedMutator() (guardops.Mutator, error) {
	if usesProxiedServer() || store == nil {
		return nil, fmt.Errorf("guard: initialized direct server storage required")
	}
	provider, ok := store.(guardops.Provider)
	if !ok {
		provider, ok = storage.UnwrapStore(store).(guardops.Provider)
	}
	if !ok {
		return nil, fmt.Errorf("guard: backend does not support guarded mutation")
	}
	return provider.GuardedMutator()
}

// Request framing is bounded before decoding. The native state is opaque;
// decoding only the outer typed envelope never recomposes stateJson bytes.
func readGuardRequest(cmd *cobra.Command, target any) error {
	path, _ := cmd.Flags().GetString("request-json")
	var reader io.Reader
	if path == "-" {
		reader = cmd.InOrStdin()
	} else {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		reader = file
	}
	// JSON escaping may expand the 16 MiB native state by up to six bytes.
	raw, err := io.ReadAll(io.LimitReader(reader, guardops.MaxWireBytes+1))
	if err != nil {
		return err
	}
	switch request := target.(type) {
	case *guardops.Request:
		*request, err = guardops.DecodeRequest(raw)
	case *guardops.LookupRequest:
		*request, err = guardops.DecodeLookup(raw)
	default:
		return fmt.Errorf("guard: unsupported request type")
	}
	return err
}

func init() {
	capture := &cobra.Command{
		Use: "capture <canonical-id>", Short: "Capture the original native issue and database state", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role, err := commandGuardedMutator()
			if err != nil {
				return err
			}
			captured, err := role.Capture(rootCtx, args[0])
			if err != nil {
				return err
			}
			return outputJSONRaw(captured)
		},
	}
	apply := &cobra.Command{
		Use: "apply", Short: "Attempt one guarded release against the original capture", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			CheckReadonly("guard apply")
			var request guardops.Request
			if err := readGuardRequest(cmd, &request); err != nil {
				return err
			}
			if err := guardops.ValidateRequest(request); err != nil {
				return err
			}
			role, err := commandGuardedMutator()
			if err != nil {
				return err
			}
			ctx, err := issueOpsContext(rootCtx)
			if err != nil {
				return err
			}
			result, _ := role.Apply(ctx, request)
			// Typed business refusals/conflicts/unknowns are protocol results.
			// A lost command response is still unknown to the caller.
			if result.Outcome == "applied" && !result.Replayed {
				commandDidWrite.Store(true)
				commandDidExplicitDoltCommit = true
			}
			return outputJSONRaw(result)
		},
	}
	lookup := &cobra.Command{
		Use: "lookup", Short: "Resolve a stable operation id and exact request digest", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var request guardops.LookupRequest
			if err := readGuardRequest(cmd, &request); err != nil {
				return err
			}
			if err := guardops.ValidateLookup(request); err != nil {
				return err
			}
			role, err := commandGuardedMutator()
			if err != nil {
				return err
			}
			result, _ := role.Lookup(rootCtx, request)
			return outputJSONRaw(result)
		},
	}
	initialize := &cobra.Command{
		Use: "initialize", Short: "Initialize an experimental disposable database under maintenance exclusivity", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			CheckReadonly("guard initialize")
			experimental, _ := cmd.Flags().GetBool("experimental")
			if !experimental || usesProxiedServer() || store == nil {
				return fmt.Errorf("guard: explicit --experimental and direct disposable server storage required")
			}
			initializer, ok := storage.UnwrapStore(store).(interface{ InitializeGuard(context.Context) error })
			if !ok {
				return fmt.Errorf("guard: backend does not support initialization")
			}
			ctx, err := issueOpsContext(rootCtx)
			if err != nil {
				return err
			}
			if err := initializer.InitializeGuard(ctx); err != nil {
				return err
			}
			commandDidWrite.Store(true)
			commandDidExplicitDoltCommit = true
			return outputJSONRaw(map[string]string{"protocol": guardops.Protocol, "outcome": "initialized"})
		},
	}
	for _, command := range []*cobra.Command{apply, lookup} {
		command.Flags().String("request-json", "", "Request JSON file, or - for stdin")
		_ = command.MarkFlagRequired("request-json")
	}
	initialize.Flags().Bool("experimental", false, "Explicitly initialize only disposable local data")
	guardCmd.AddCommand(capture, apply, lookup, initialize)
	rootCmd.AddCommand(guardCmd)
}
