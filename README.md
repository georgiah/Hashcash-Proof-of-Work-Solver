# Server-based proof-of-work solver for the Hashcash mining algorithm

## Introduction
The Hashcash algorithm can be described as follows:

```
Find x such that H(H(x)) = y, where y < target
```

- `H` is the SHA-256 hash function
- `target` is an unsigned 256-bit integer, which represents the largest acceptable hash value of some input

    `target` is calculated from an 8-byte hexadecimal `difficulty` using the following formula:

    &nbsp;&nbsp;&nbsp;&nbsp;`target` = β × 2<sup>8 × (α - 3)</sup>  

    &nbsp;&nbsp;&nbsp;&nbsp;where α = `difficulty[0..7]`, and β = `difficulty[8..31]`

- `x` is defined as a `seed` value concatenated with some `nonce`, i.e. `seed | nonce`

   `seed` is a 64 byte array

   `nonce` is a 64 bit unsigned integer

The goal is to find a `nonce` value, which when concatenated with a provided `seed`, provides a hash that is less than a provided `target`.
To do this, the search starts from some initial `nonce` and validates whether the conditions hold. If they do not, the `nonce` is increased until they do.

This program is a proof-of-work solver that is server based. Clients can connect to the server to send requests for it to respond to. It is capable of handling up to 100 clients.

This program uses a simple protocol to format messages between the server and a client. It is a _requirement_ of the protocol that all messages end with the delimiter `\r\n`.
The program consists of seven messages that the client may send to the server:
- `PING`
    + The server responds `PONG`

- `PONG`
    + The server responds `ERRO PONG reserved for server responses`

- `OKAY`
    + The server responds `ERRO invalid sequence of messages`

- `ERRO`
    + The server responds `ERRO server does not handle ERRO messages`

- `SOLN difficulty:uint32 seed:BYTE[64] solution:uint64`
    + For example, `SOLN 1fffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 10000000232123a2`
    + The server validates whether the concatenation of the `seed` and the `solution` (i.e. a `nonce` value) produces a hash that meets the `target` requirement. If it does, the server responds `OKAY`. If it does not, the server responds `ERRO not a valid solution`.

- `WORK difficulty:uint32 seed:BYTE[64] start:uint64 worker_count:uint8`
    + For example, `WORK 1fffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 1000000023212399 02`
    + The server now needs to _find_ a valid solution. `start` is the value that `nonce` should be initialised with to begin the search. `worker_threads` is the number of threads the server should use to complete the computation.
    + Once a solution is found, the server responds `SOLN difficulty:uint32 seed:BYTE[64] solution:uint64`. For example, `SOLN 1fffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 1000000023212605`

- `ABRT`
    + The server will remove all current and pending work for the client that sent this message. The server responds `OKAY`


## Environments
This application was developed on `Linux 2.6.32-642.1.1.el6.x86_64`. It has also been tested on `Mac OS High Sierra 10.13.2`. It has most definitely _not_ been tested on Windows.

## Installation
To install and run this project, clone and then navigate to the repository.
To compile the code, you will need a C compiler. I recommend `gcc`. If you have `gcc` installed, you can compile the code by running:

```
make server
```

You may see a lot of warnings. Unless you see an error, don't be concerned.

## Usage
To start the server with port number 12345:

```
./server 12345
```

Any port number from 1024 - 49151 that isn't being using by another running application can be chosen

The server will now sit and patiently await a request. Let's send it one.

You can do so from your own computer by spinning up another terminal. You are more than welcome to write a client program, but we can also communicate by using `telnet` or `netcat`. Let's use `netcat`. Since we're communicating to ourselves, we can just use our local IP:

```
nc 127.0.0.1 12345
```

Make sure the actual port number you've chosen for the server is entered. Now we've connected, we can send messages to the server. **BUT** be careful - remember that the protocol _requires_ all messages must end with `\r\n`, not just a simple linebreak.

The command for `\r` can be found by typing in the command:

```
stty -a
```

and scanning for `lnext` - literal next. On my computer it is `^V`. So, on my computer, to delimit the message, I need to enter `Control + V`, then hit `Return` twice to send the message.

Sending a `PING` message looks like this:

![PING^M PONG](images/PING-PONG.png)

Here are some sample `SOLN` and `WORK` messages you can try out:
- `SOLN 1fffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 1000000023212605`
- `SOLN 1fffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 1000000023212143`
- `SOLN 1effffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 100000002321ed8f`
- `WORK 1fffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 1000000023212000 01`
- `WORK 1fffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 1000000023212399 02`
- `WORK 1effffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 1000000023212399 04`
- `WORK 1dffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 1000000023212399 01`

You might find that one or two of them takes a little while to calculate. You can test that the server is capable of handling multiple clients by opening up a couple of terminals, connecting each to the server, and sending multiple messages. Here's an example:

![Multiple clients demonstration](images/demo.gif)

The server can also be accessed from another computer by using your machine's private IP address in the `nc` command. You can find this can running the command `ifconfig` and looking for the IP address listed beside `inet`.

## Discussion
> That's one big file

It was a requirement for this project that the server code (that is, all code except the provided `sha256.c` and `uint256.h`) be developed in a single file. I have not yet modularised the program into multiple files due to some persistent linking issues when compiling on my machine.

> Why have the delimiter string?

The delimiter string `\r\n` may seem annoying to have to remember when communicating with the server. However, including it ensures that the client is at least somewhat familiar with the protocol, which they do need to be in order to do anything useful with the server.

If you'd prefer to change what is used as a delimiter, just update the definition of `DELIMITER` at line 24.

> Can I use this to mine Bitcoin?

You can fork this code and do whatever you like with it. However, it was not intended to be used to mine. Its primary purpose was to explore TCP sockets and multithreading with some non-trivial computation. You can find out more about Hashcash [here](https://en.bitcoin.it/wiki/Hashcash), and mining [here](https://en.bitcoin.it/wiki/Mining).

## License
MIT
