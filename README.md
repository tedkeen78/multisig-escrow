# Multsig Escrow Manager

Bitcoin allows for complex types of transactions, including multisignature
transactions, which can be used to implement an Escrow system that minimizes
the risk of the Arbitrator stealing the payment. However, it's not
straight-forward to users how to use those types of transactions.

This web application aims to provide a location where users can keep track of
Escrow payments, to inform them how to manage multisig transactions, and to
keep track of partially-signed transactions completing the payment.

The multisig/bitcoin parts aren't completed yet.

## Installation

This project uses nodejs. Make sure you have that installed.

Use `npm install` to install of the required dependencies and to compile the
project.

Copy "config-example.json" to "config.json" and then customize its values.

* `secret` must be a random unpredictable string.

* `audience` must be set to the domain that the web app is accessed by and must
  have the protocol and port number. This is used by Persona.

* `approot` must be set to the path the web app is accessed by. This must be
  changed if you're hosting this app under a subdirectory by an nginx proxy
  redirect for example.

* `trust_proxy` can be set to true to trust "X-Forwarded-Proto",
  "X-Forwarded-Host", and "X-Forwarded-For" headers. This is an Express
  setting.

* `ga` is optional and is for Google Analytics values.

* The `socket` values can be set to a path to a UNIX socket.

* redis is optionally used for sessions currently (sqlite will be
  automatically be used as fallback). The redis:cache values are
  intended to refer to a secondary redis daemon that does not persist
  its memory to disk, but it isn't used yet.

* `admin:email` is an address displayed on error pages if set.

Use `NODE_ENV=production node app.js` to run the web app.
