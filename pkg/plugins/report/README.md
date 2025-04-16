# QPoint Report Plugin

This plugin captures the request and response payload and passes these requests to Qtap ingestion (out of band). This plugin runs on 10080 by default. This plugin submits batches of request reports on a 5 second tick, out of band of the user.

#### Configuration options:

- `pulse_endpoint`: an endpoint for submitting pulse report requests.
- `pulse_token`: the bearer token to access a pulse endpoint within the Authorization header (eg. `Authorization: Bearer <pulse_token>`).
- `batch_period_ms`: delay between batch submissions in milliseconds (defaults to 5 seconds).
- `tags`: a string array of static tags that will be appended to every report request.
