## ADDED Requirements

### Requirement: Pairwise salt is install-generated and non-rotating

The system SHALL generate a pairwise salt from the OS CSPRNG at first
boot when none is configured. It SHALL fail boot if the configured
value is empty or a placeholder. The committed tree SHALL NOT contain
a usable default salt. The salt SHALL NOT appear in logs or `/health`.
Rotation SHALL be unsupported.

#### Scenario: First boot creates a salt

- GIVEN no pairwise salt is configured
- WHEN the server boots
- THEN a salt is generated and subsequent pairwise `sub` values are
  stable for that deployment

#### Scenario: Placeholder salt fails closed

- GIVEN `IDENTIKEY_PAIRWISE_SALT` is empty or a known placeholder
- WHEN the server boots
- THEN boot fails and names the salt
