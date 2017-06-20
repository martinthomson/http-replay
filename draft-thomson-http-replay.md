---
title: Using TLS Early Data in HTTP
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
    organization: Exceliance
    email: w@1wt.eu


informative:

--- abstract

TLS early data presents both an opportunity and a risk.  The risks of using TLS
early data are explained as they relate to HTTP.  A technique for reducing
these risks is described, including mechanisms that enable the use of that
technique at intermediaries.


--- middle

# Introduction

TLS 1.3 {{?TLS13=I-D.ietf-tls-tls13}} introduces the concept of early data, or
zero round trip data.  Early data allows a client to send data to a server in
the first round trip of a connection, without waiting for the TLS handshake to
complete, if the client has spoken to the same server recently.

For HTTP {{!HTTP=RFC7230}}, early data allows clients to send requests
immediately, avoiding the one or two round trip time needed for the TLS
handshake.  This is a significant performance enhancement, however early data
has some significant limitations.

The primary cost of using early data is the risk that an attacker might capture
and replay the early data.  TLS {{!TLS13}} describes techniques that reduce the
likelihood that an attacker can successfully replay a request, but these
techniques can be difficult to deploy and it could be impossible to guarantee
perfect protection against replay attack.

This document explores how HTTP treats both retries and replays of requests.

To help mitigate the risk of replay, a technique for controlling the risks
inherent to the use of early data is outlined, including a mechanism that grants
a gateway the ability to apply this technique.  This technique ensures that the
choice to expose a request to the possibility of replay is mutual: client and
server will both need to agree to accept the risk.

The advice in this document also applies to use of 0-RTT in HTTP over QUIC
{{?HQ=I-D.ietf-quic-http}}.


# Conventions and Definitions

The words "MUST", "MUST NOT", "SHOULD", and "MAY" are used in this document.
It's not shouting; when they are capitalized, they have the special meaning
defined in {{!RFC2119}}.


# Retries in HTTP

In many circumstances, HTTP requests are retried.  Applications care about
reliability and will frequently retry requests in the event of errors.  Many
HTTP libraries or intermediaries automatically retry requests in certain
conditions.

Idempotent methods {{?RFC7231}} are specifically defined to support automatic
retry.  Processing a request with an idempotent method more than once does not
result in a different end state.  HTTP/2 {{?HTTP2=RFC7540}} also defines
circumstances in which automatic retry of a request does not result in duplicate
processing at a server, allowing retry of requests with non-idempotent methods.

However, many clients will retry a request even if a retry is not safe.  For
instance, many clients will retry POST requests if a connection is terminated
before any octets of a response are received.  Even in the absence of automatic
retries, when errors are presented to users, users might initiate a retry, by
pressing a "reload" button or re-initiating a transaction.

The prevalence of retries means that applications that use HTTP SHOULD implement
measures for detecting and rejecting unwanted retries.  This can be seen as an
application of the end-to-end principle of system design
{{?E2E=DOI.10.1145/357401.357402}}: no protocol is expected to simultaneously
provide a guarantee of at-most-once delivery and error tolerance.


# TLS Early Data in HTTP

A server can decide whether or not to offer clients the ability to send early
data.  This decision is made when sending a session ticket to clients.

A client that wishes to use early data commences sending requests immediately
after sending the TLS ClientHello.  If early data is accepted, early data is
concatenated with other application to form a single stream of data.

A server cannot choose to selectively reject early data.  TLS only permits a
server to accept all early data, or none of it.  Once a server has decided to
accept early data, it MUST process the messages that are sent by the client in
early data.

If a server rejects early data, a client MUST start sending again as though the
connection was new.  For HTTP/2, this means re-sending the connection preface.
Any requests sent in early data MUST be sent again, unless the client decides to
abandon those requests.

This results in a potential replay where the early data is sent to one server
instance and the connection attempt is separately allowed to complete where the
server instance rejects the early data.  Replays are also possible if there are
multiple server instances that will accept early data, or if the same server
accepts early data multiple times (though this would be in violation of
requirements in TLS).


# Replay Attacks

What distinguishes a replay attack from a retry is that a retry is explicitly
initiated by a client or user.  In contrast, a
replay attack is initiated by an attacker.  The attacker creates a copy of the
messages sent by a client and replays these messages without the knowledge or
consent of the client.

For application data that is sent after the TLS handshake completes, TLS
provides protection against replay.  Duplicated data is detected and treated as
a fatal error condition (in DTLS {{?DTLS=RFC6347}}, duplicated data is instead
discarded).  Similarly, transport layer loss recovery, such as TCP
retransmission, does not generate replays because the transport discards
duplicated data.

TLS early data creates the potential for a replay attack that cannot be detected
by TLS or the transport protocol.  TLS {{?TLS13}} describes several mitigation
strategies that reduce the ability of an attacker to successfully replay early
data.  Servers are strongly encouraged to implement these techniques, but to
also recognize that they are imperfect.


# Reducing the Risk of Replay

It is immediately obvious that a client can make an explicit choice on each
request it makes as to whether it sends that request in early data.  This gives
a client explicit control over whether a given request is exposed to the risk of
replay.

A server can also choose whether it processes early data before the TLS
handshake completes.  By deferring processing for a request until the handshake
is complete, it can ensure that only a successfully completed connection is used
for processing early requests.  Assuming that a replayed ClientHello will not
result in additional connections being made by the client, this provides the
server with some assurance that the early data was not replayed.

If the server receives multiple requests in early data, it can make a
determination about whether to defer processing on a per-request basis.

The amount of data that a client can send in early data can be limited by a
server using the `max_early_data_size` field that is sent when a server enables
early data.  A server can use this to avoid having to commit an arbitrary amount
of memory for deferred requests.  A server SHOULD ensure that when it accepts
early data, it can defer processing of requests until after the TLS handshake
completes.

Using this technique ensures that, for any given request, both client and server
need to agree to accept the risk of replay if that risk exists.


# Replay Avoidance for Gateways

A generic gateway might be unable to make a determination about whether a given
request can be processed safely when it is sent in early data.  In many cases,
only the origin server has the necessary information to decide whether the risk
of replay is acceptable.

This leads to a strong incentive for gateways to be quite conservative, either
disabling early data entirely, or only allowing a narrow subset of requests to
be forwarded.

To improve the ability of a gateway to accept and forward requests that arrive
in early data, two signaling mechanisms are defined:

* The `Early-Data` header field is added to any request that is sent or
  received in early data.

* The 422 (Too Early) status code is defined for an origin server to indicate
  that a request could not be processed due to the consequences of a possible
  replay attack.

In order for this technique to work well, the gateway needs to be certain that
the origin server will understand the `Early-Data` header field and correctly
generate the 422 status code if it does not wish to process the request.


## The Early-Data Header Field

The `Early-Data` header field is defined with two values, "0" and "1".  Here it
is shown using the ABNF {{!ABNF=RFC5234}}:

~~~
Early-Data = "0" / "1"
~~~

For example:

~~~
POST /resource HTTP/1.0
Host: example.com
Early-Data: 1
Content-Length: 14

message body
~~~

A client SHOULD include the `Early-Data` header field with a value of "1" if it
sends a request in TLS early data.  This indicates to the intermediary or server
that it understands the 422 (Too Early) status code and is prepared to retry
the request.

The `Early-Data` header field is omitted from a request or set to "0" when the
request arrives after the TLS handshake completes.  An intermediary MUST NOT add
this header field with a value of "0" or remove a header field if it has a value
of "1".

A `Early-Data` header field with a value of "1" is added to a request when
forwarding a request from a connection that has an incomplete TLS handshake.  In
other words, a value of "1" identifies requests that were sent in TLS early
data.  A value of "1" indicates that the request might have been replayed.

An intermediary that receives a request in TLS early data can forward the
request with the `Early-Data` header field add and set to "1".  If the server
responds with a 422 (Too Early) status code, the intermediary can then wait
until the TLS handshake completes and forward the request again, or simply
pass the status code back to the client which will be able to retry appropriately.


## The 422 (Too Early) Status Code

A 422 (Too Early) status code indicates that the server that is unwilling to
risk processing requests that might be replayed.

The primary use of this header field is to cause clients or intermediaries to
retry a request.  A client or intermediary MAY retry any request automatically
if they receive a 422 (Too Early) status code.  A request that receives a 422
(Too Early) status code MUST NOT be retried in TLS early data.

An intermediary that forwards a request SHOULD wait until the TLS handshake on
the connection that carries the original request is complete before retrying.
If the original request that arrived at the intermediary contained an
`Early-Data` header field with a value of "1", the intermediary MAY instead
forward the 422 (Too Early) status code.

A server SHOULD NOT generate the 422 (Too Early) status code unless the request
includes an `Early-Data` header field with a value of "1".


# Security Considerations

Using early data exposes a client to the risk that their request is replayed.  A
retried or replayed request can produce different side effects on the server.
That might be used for traffic analysis to recover information about requests or
the resources those requests target.

A gateway that forwards requests that were received in early data MUST only do
so if it knows that the server that receives those requests understands the
`Early-Data` header field and will correctly generate a 422 (Too Early) status
code.  A gateway that isn't certain about server support SHOULD either delay
forwarding the request until the TLS handshake completes, or send a 422 (Too
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

This document registers the 422 (Too Early) status code in the "Hypertext
Transfer Protocol (HTTP) Status Code" registry established in {{!RFC7231}}.

Value:

: 422

Description:

: Too Early

Reference:

: This document


--- back
