package main

import "net/http"

/*

Security Through Obscurity

Why is this here?  Everybody knows STO has a questionable history.

Here is the scenario...

If someone is able to gain access to the database, they know that the encrypted values are not
recoverable from the server since they use private keys that the server has no access to.  However,
they may be interested in learning which IP sent the message they cannot read.  The problem here
is that 2^32 and 2^64 just are not that big.  If they could read the database AND were able to send
requests to the server with any IP in the associated header (a very serious compromise), they
could work backwards from there.  This is even simpler if they have an idea about which networks
to test.  So we need something to prevent them from just feeding in a bunch of requests with IPs
until they find a match to the message in question.

We need some sort of processing that is very close to as deterministic as just the IP for our
spam tracking, but also prevents someone from just feeding in a bunch of addresses until they
find a match.

And to solve this we...

Haha - its obscure remember!

The below function does nothing - only the real server runs the actual code

*/

func stoHIPSecret(req *http.Request) []byte {
	return nil
}
