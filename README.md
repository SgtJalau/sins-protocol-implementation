# SINS Protocol Implementation

This project is a small Java implementation of the SINS protocol for a university security protocol assignment. It contains a client, a server, shared protocol message logic, crypto helpers, socket transport and tests.

## Requirements

- Java 25
- Maven

The project is a Maven project and can be opened directly in IntelliJ IDEA.

## Run The Demo

The demo entry point is:

```text
src/main/java/me/charlie/sinsprotocol/SinsProtocolDemo.java
```

The easiest way to run it is from IntelliJ:

1. Open the project.
2. Open `SinsProtocolDemo.java`.
3. Run the `main` method.

The demo starts a local socket server on a random free port, creates a client, performs the protocol handshake, exchanges encrypted sensor readings, prints the packets, and then shuts the session down.

You can also run it from Maven:

```powershell
mvn compile exec:java -Dexec.mainClass="me.charlie.sinsprotocol.SinsProtocolDemo"
```

If Maven does not use Java 25 by default, set `JAVA_HOME` first:

```powershell
$env:JAVA_HOME='Path\To\Java25'
$env:PATH="$env:JAVA_HOME\bin;$env:PATH"
mvn compile exec:java -Dexec.mainClass="me.charlie.sinsprotocol.SinsProtocolDemo"
```

## Run Tests

```powershell
mvn test
```

The tests include the normal protocol flow, socket communication, replay rejection, invalid authentication, tampering, sequence checks, epoch checks and close handling.

## Project Structure

```text
src/main/java/me/charlie/sinsprotocol
```

- `SinsProtocolDemo.java`: runnable showcase for the protocol over a local TCP socket.
- `client`: client state machine, client-side message handling and socket client wrapper.
- `server`: server state machine, sensor reading provider, server-side message handling and socket server wrapper.
- `protocol/message`: protocol packet records and message field parsing.
- `protocol/codec`: canonical JSON encoding and decoding for packets.
- `protocol/crypto`: key exchange, HKDF, HMAC, AES-GCM and transcript hashing helpers.
- `protocol/exception`: protocol-specific exception type.
- `transport`: socket framing for packets.
- `util`: demo/logging helpers.

```text
src/test/java/me/charlie/sinsprotocol
```

- `SinsProtocolSimulationTest.java`: protocol and socket tests.
