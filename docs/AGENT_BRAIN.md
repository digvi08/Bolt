# Agent Brain and Safe Task Planning

The agent brain is the planning layer. It interprets natural-language requests, selects a safe ability, creates a typed plan, and then hands execution back to the trusted runtime and policy engine.

## Flow

User request
  -> Task interpreter
  -> Context compiler
  -> Model router
  -> Deterministic planner
  -> Plan validator
  -> Ability registry lookup
  -> Policy / approval gate
  -> Trusted runtime execution
  -> Observation / verification
  -> Recovery / replan (bounded)

## Trust model

The system distinguishes:

- Trusted System
- Trusted User
- Trusted Memory
- Untrusted Web
- Untrusted Document
- Untrusted Tool Output

External content is never allowed to become a system instruction. Prompt-injection attempts remain clearly labeled as untrusted content and are never promoted.

## Model interfaces

The model provider abstraction is intentionally vendor-neutral. It supports:

- generate()
- structured_generate()
- bounded fallback
- model/latency/cost tracking

The default deterministic provider is used for validation and offline testing. Real model adapters remain optional and configuration-driven.

## Safe action generation

Model-created actions are validated before execution:

- schema validation
- ability registration lookup
- unknown ability rejection
- unknown action rejection
- risk / verification checks
- runtime policy evaluation

The model cannot approve its own action. Approval still originates from the existing approval abstraction.

## Budgeting and failure handling

The planner and executor enforce bounded budgets for:

- plan steps
- replans
- model calls
- recoveries

When the policy or runtime rejects a plan, the agent brain records the failure and stops without escalating to arbitrary execution.

## Ability integration

The brain uses the existing `AbilityRegistry` instead of a second independent list of abilities. This keeps browser and desktop actions aligned with the same allowlist, policy, and approval rules.

## Important security note

The model is a planner/reasoner only. It is not an execution authority.
