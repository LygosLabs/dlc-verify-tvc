# Release identity

The StageX workflow emits `release-manifest.json` after pushing an immutable image. That build artifact binds the source commit, frozen DLC Verify target, `Cargo.lock`, OCI image, `/tvc_app` digest, platform, arguments, ports, debug state, and intended egress state. It deliberately sets `deploymentIdentity` to `null` and `authorizationReady` to `false` because CI has not observed a live TVC deployment.

For a deployed release:

1. Copy `release-manifest.example.json` and fill every value from the immutable build and verified live deployment.
2. Copy `trusted-release-policy.example.json` into the relying party's separately controlled trust store; never derive trusted values from the Boot Proof under test.
3. Fetch the Boot Proof by the exact App Proof ephemeral public key.
4. Run the official proof and `verifier-client` checks, compare the request digest and one-time challenge, and independently authenticate the deployment-only `pivotPath` and `enableEgress` controls.
5. Set `authorizationReady` to `true` only after the non-debug, egress-disabled deployment is 3/3 healthy and valid, invalid, malformed, oversize, concurrency, and proof canaries pass.

Publishing an image, creating a TVC application, deploying, or setting a deployment live requires separate operational authorization.
