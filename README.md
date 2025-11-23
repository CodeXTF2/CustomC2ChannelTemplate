# IAT Hooking for custom C2 channels

This is a simple PoC and template for developing custom C2 channels for Cobalt Strike using IAT hooks applied by a reflective loader.

Demo gif of the TCP channel
![gif.gif](https://github.com/CodeXTF2/CustomC2ChannelTemplate/blob/main/gif.gif?raw=true)

## Usage
the hook.c, hash.h and hook.h files are rough templates, but they can be dropped into [Crystal kit](https://github.com/rasta-mouse/Crystal-Kit) to be used as is as a PoC. Place them into the udrl/src folder, replacing the existing copies. tcg.h is unchanged (from Raphael Mudge's tradecraft garden)

Examples in the examples/ folder can be used as is, but they are **examples** and operational considerations were not taken when writing them. Use with caution.

Current examples are:
- named pipe (broker must run on same host)
- TCP
- UDP (I was too lazy to do chunking, so max callback size of 65535)


Note that original evasion capabilities in Crystal kit such as the Draugr implementation and sleep masking have been removed from the hook.c to keep this codebase clean and portable. If you wish to keep those features, you can add them back from the original copies in Crystal kit.

You must select wininet as the http library to use when generating the beacon dll.

## Why did I make this?
The official ExternalC2 interface is a pain to use - it requires staging of an SMB beacon OVER the externalc2 channel, and (until 4.10) did not support communicating with a premade SMB beacon without staging through the externalc2 agent first. Even in its current state, it is still tied to the architecture of:  
```
smb beacon --named pipe--> externalc2 agent --custom channel--> externalc2 handler --> teamserver
```

Yes, I am aware of UDC2 being added in Cobalt Strike 4.12. This is just a fun experiment anyway to replicate that capability in the UDRL.

The concept is simple - if you can hook the WinAPIs used to call back, you already have all the data necessary for a callback. This method of implementing custom C2 channels has already been done before, as seen in [GraphStrike](https://github.com/RedSiege/GraphStrike). 

However, GraphStrike's implementation is still quite tied to the HTTP protocol itself. The goal of this repo is to provide an easy to use, modify and extend template for implementing any custom channel, HTTP or otherwise, with little modification to the surrounding code. 

## Extending the template
This template is obviously not meant to be used in its default state, so to implement your C2 channel of choice, you need to modify the
following:

```customCallback``` function to perform the following things:

1. transmit the base64 blob (its only argument) out via any means necessary
2. write it to a char*
3. return that char*

and modify the ```handleCallback()``` function in broker.py to do the following:

1. receive callbacks
2. call process_encoded_request(your callback data goes here)
3. send responses back.

Thats it.

As an example, the PoC in the ```customCallback()``` function in the hook.c currently does the following:

1. write the base64 blob to a file, request.txt
2. waits 500ms
3. reads the response from a file response.txt
4. returns the file contents

The PoC in the handleCallback function in the broker.py currently does the following:

1. reads callback from request.txt
2. calls ```process_encoded_request(encoded_request)```
3. writes the response to response.txt

```usage: broker.py [-h] --host HOST --port PORT```
where the host and port points to the http listener on your teamserver. The broker parses out the http request and sends it to the actual
listener.

## Other random fun facts about this implementation, for anyone that cares
This is probably the "laziest" way I to do it, but also one of the more stable ways. It basically just wraps up the entire HTTP request up and ships it over to the broker however you want, which then sends it to the teamserver for real, to run as a HTTP beacon, totally transparent to the teamserver.

There is a (technically) cleaner implementation that I tried that involved using a barebones Malleable C2 profile (I used the one from graphstrike, actually) and parsing out the different beacon data components as per the malleable spec inside the wininet hooks themselves (id, metadata, output etc). This would have made the callback blob sizes slightly smaller, but that implementation was abandoned as the codebase became unnecessarily messy due to the request parsing and also required use of that specific profile (which isnt that big a deal but is a big hacky).

This implementation I felt was better because it is less dependent on the hacky malleable profile (technically, it still requires beacon response output to be sent in the response body, but thats the only requirement) and the code was 10x easier to read. 

Also worth noting that there is no obfuscation or encryption on the http request json other than base64 encoding - you are free to add your own, but since Beacon callbacks are already encrypted, technically no data is at risk of being decrypted. The worst that could happen is that the base64 blob if retrieved could be identified as a HTTP request. Do with that information what you will.

## Credits and references
- https://github.com/rasta-mouse/Crystal-Kit (Original template for dev and testing) 
- https://github.com/RedSiege/GraphStrike (IAT hooking to implement a Graph channel)
- https://github.com/benheise/TitanLdr (IAT hooking to implement DoH)
- https://tradecraftgarden.org/ (framework used for crystal kit, and by extension this)

Yes I used an LLM to write some of the code and comments, nobody likes writing docs or writing boilerplate json parsing in C from scratch. Sue me.

# Disclaimer
Usual disclaimer, I am not responsible for any crimes against humanity you may commit or nuclear way you may cause using this piece of poorly written code



