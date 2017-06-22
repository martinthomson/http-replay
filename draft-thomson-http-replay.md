---
title: Using Early Data in HTTP
abbrev: HTTP Early Data
docname: draft-thomson-http-replay-latest
category: std

ipr: trust200902
area: ART
workgroup: httpbis
keyword: Internet-Draft

stand_alone: yes
pi: [toc, tocindent, sortrefs, symrefs, strict, compact, comments, inline, docmapping]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    organization: Mozilla
    email: martin.thomson@gmail.com
 -
    ins: M. Nottingham
    name: Mark Nottingham
    organization: Yes
    email: mnot@mnot.net
 -
    ins: W. Tarreau
    name: Willy Tarreau
    organization: HAProxy Technologies
    email: willy@haproxy.org


informative:

--- abstract

This document explains the risks of using early data for HTTP and describes
techniques for reducing them. In particular, it defines a mechanism that
enables clients to communicate with servers about early data, to assure correct
operation.


--- middle

# Introduction

TLS 1.3 {{?TLS13=I-D.ietf-tls-tls13}} introduces the concept of early data
(also known as zero round trip data). Early data allows a client to send data
to a server in the first round trip of a connection, without waiting for the
TLS handshake to complete if the client has spoken to the same server recently.

For HTTP {{!HTTP=RFC7230}}, early data allows clients to send requests
immediately, avoiding the one or two round trip delay needed for the TLS
handshake. This is a significant performance enhancement; however, it has
significant limitations.

The primary risk of using early data is that an attacker might capture and
replay the request(s) it contains. TLS {{!TLS13}} describes techniques that can
be used to reduce the likelihood that an attacker can successfully replay a
request, but these techniques can be difficult to deploy, and still leave some
possibility of a successful attack.

Note that this is different from automated or user-initiated retries; replays
are under the control of an attacker, and are therefore malicious.

To help mitigate the risk of replays in HTTP, this document gives an overview
of techniques for controlling these risks. It also defines a mechanism that
enables clients to communicate with origin servers about early data, to assure
correct operation.

The advice in this document also applies to use of 0-RTT in HTTP over QUIC
{{?HQ=I-D.ietf-quic-http}}.


## Conventions and Definitions

The words "MUST", "MUST NOT", "SHOULD", and "MAY" are used in this document.
It's not shouting; when they are capitalized, they have the special meaning
defined in {{!RFC2119}}.


# Supporting Early Data in HTTP Servers

A server decides whether or not to offer a client the ability to send early
data on future connections when sending the TLS session ticket.

When early data is enabled by the server, there are a number of techniques it
can use to mitigate the risks of replay:

1. The server can choose whether it processes early data before the TLS
handshake completes. By deferring request processing until the handshake is
complete, it can ensure that only a successfully completed connection is used
for processing those requests. Assuming that a replayed ClientHello will not
result in additional connections being made by the client, this provides the
server with some assurance that the early data was not replayed.

2. If the server receives multiple requests in early data, it can determine
whether to defer HTTP processing on a per-request basis. When doing so, it
SHOULD defer any requests that have state-changing side effects on the server.
If this is not known by the server, it MUST defer the request.

3. When a request received in early data contains the `Early-Data` request
header field ({{header}}), the server can trigger a retry without the use of
early data by responding with the 4NN (Too Early) status code ({{status}}), in
cases where the risk of replay is judged too great.

4. Finally, TLS {{?TLS13}} describes several mitigation strategies that reduce
the ability of an attacker to successfully replay early data. Servers are
strongly encouraged to implement these techniques, but to also recognize that
they are imperfect.

Note that a server cannot choose to selectively reject early data. TLS only
permits a server to accept all early data, or none of it. Once a server has
decided to accept early data, it MUST process all requests in early data, even
if the server rejects the request by sending a 4NN (Too Early) response.

A server can limit the amount of early data with the `max_early_data_size`
field. This can be used to avoid committing an arbitrary amount of memory for
deferred requests. A server SHOULD ensure that when it accepts early data, it
can defer processing of requests until after the TLS handshake completes.


# Using Early Data in HTTP Clients

A client that wishes to use early data commences sending HTTP requests
immediately after sending the TLS ClientHello.

By their nature, clients have control over whether a given request is sent in
early data -- thereby giving the client control over risk of replay. Absent
other information, clients MAY send requests with safe HTTP methods in early
data when it is available, and SHOULD NOT send unsafe methods (or methods whose
safety is not known) in early data.

If the server rejects early data, a client MUST start sending again as though
the connection was new. For HTTP/2, this means re-sending the connection
preface. Any requests sent in early data MUST be sent again, unless the client
decides to abandon those requests.

This automatic retry exposes the request to a potential replay attack.  An
attacker sends early data to one server instance that accepts and processes the
early data, but allows that connection to proceed no further.  The attacker then
forwards the same messages from the client to another server instance that will
reject early data.  The client the retries the request, resulting in the request
being processed twice.  Replays are also possible if there are multiple server
instances that will accept early data, or if the same server accepts early data
multiple times (though this would be in violation of requirements in TLS).

Clients MUST identify requests sent in early data with the `Early-Data` request
header field; see {{header}}. Clients that use early data MUST retry requests
upon receipt of a 4NN (Too Early) status code; see {{status}}.

Clients MUST NOT use early data in requests when a proxy is configured.

An intermediary MUST NOT use early data when forwarding a request unless early
data was used on a previous hop.  That means that an intermediary can only use
early data if the request that either arrived in early data or arrived with the
`Early-Data` header field set to "1".


# Extensions for Early Data in HTTP

Because HTTP requests can span multiple "hops", it is necessary to explicitly
communicate whether a request has been sent in early data on a previous
connection. Likewise, some means of explicitly triggering a retry when early
data is not desirable is necessary. Finally, it is necessary to know whether the
client will actually perform such a retry.

To meet these needs, two signaling mechanisms are defined:

* The `Early-Data` header field is added to any request that is received in
  early data.

* The 4NN (Too Early) status code is defined for an origin server to indicate
  that a request could not be processed due to the consequences of a possible
  replay attack.

They are designed to enable better coordination of the use of early data
between the user agent and origin server, and also when a gateway (also
"reverse proxy", "Content Delivery Network", or "surrogate") is present.

Gateways typically don't have specific information about whether a given
request can be processed safely when it is sent in early data. In many cases,
only the origin server has the necessary information to decide whether the risk
of replay is acceptable. These extensions allow coordination between a gateway
and its origin server.


## The Early-Data Header Field {#header}

The `Early-Data` request header field indicates that the request has been
conveyed in early data, and additionally indicates that a downstream client
understands the 4NN (Too Early) status code.

It has two possible values, "0" and "1". Its syntax is defined by the following
ABNF {{!ABNF=RFC5234}}:

~~~
Early-Data = "0" / "1"
~~~

For example:

~~~
GET /resource HTTP/1.0
Host: example.com
Early-Data: 1
~~~

An intermediary that forwards a request received in TLS early data MUST send it
with the `Early-Data` header field set to "1" (i.e., it adds it if not present
in the request).

An intermediary MUST NOT add this header field with a value of "0" or remove it
if it has a value of "1".

The `Early-Data` header field is not intended for use by user agents (that is,
the original initiator of a request).  Sending a request in early data implies
that the client understands this specification and is willing to retry a request
in response to a 4NN (Too Early) status code.  A user agent that sends a request
in early data does not need to include the `Early-Data` header field.


## The 4NN (Too Early) Status Code {#status}

A 4NN (Too Early) status code indicates that the server is unwilling to risk
processing a request that might be (or has been) replayed.

Clients (user-agents and intermediaries) that sent the request in early data
MUST automatically retry the request when receiving a 4NN (Too Early)
response status code. Such retries MUST NOT be sent in early data, and SHOULD
NOT be sent if the TLS handshake on the original connection does not
successfully complete.

Intermediaries that receive the 4NN (Too Early) status code MUST NOT
automatically retry requests when the original request already contained the
`Early-Data` header field with a value of "1" or the request arrived at the
intermediary in early data; instead, they MUST forward the 4NN (Too Early)
response to the upstream client.

The server cannot assume that a client is able to retry a request unless the
request is received in early data or the `Early-Data` header field is set to
"1".  A server SHOULD NOT emit the 4NN status code unless one of these
conditions is met.

The 4NN (Too Early) status code is not cacheable by default. Its payload is not
the representation of any identified resource.


# Security Considerations

Using early data exposes a client to the risk that their request is replayed.  A
retried or replayed request can produce different side effects on the server.
That might be used for traffic analysis to recover information about requests or
the resources those requests target.

A gateway that forwards requests that were received in early data MUST only do
so if it knows that the server that receives those requests understands the
`Early-Data` header field and will correctly generate a 4NN (Too Early) status
code.  A gateway that isn't certain about server support SHOULD either delay
forwarding the request until the TLS handshake completes, or send a 4NN (Too
Early) status code in response.


# IANA Considerations

This document registers the `Early-Data` header field in the "Message Headers"
registry {{!HEADERS=RFC3864}}.

Header field name:

: Early-Data

Applicable protocol:

: http

Status:

: standard

Author/Change controller:

: IETF

Specification document(s):

: This document

Related information:

: (empty)

This document registers the 4NN (Too Early) status code in the "Hypertext
Transfer Protocol (HTTP) Status Code" registry established in {{!RFC7231}}.

Value:

: 4NN

Description:

: Too Early

Reference:

: This document


--- back
