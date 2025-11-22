# IAT Hooking for custom C2 channels

This is a simple PoC and template for developing custom C2 channels for Cobalt Strike using IAT hooks applied by a reflective loader.

## Why did I make this?
The official ExternalC2 interface is a pain to use - it requires staging of an SMB beacon OVER the externalc2 channel, and (until 4.10) did not support communicating with a premade SMB beacon without staging through the externalc2 agent first. Even in its current state, it is still tied to the architecture of:  
```
smb beacon --named pipe--> externalc2 agent --custom channel--> externalc2 handler --> teamserver
```

Yes, I am aware of UDC2 being added in Cobalt Strike 4.12. This is just a fun experiment anyway to replicate that capability in the UDRL.

The concept is simple - if you can hook the WinAPIs used to call back, you already have all the data necessary for a callback. This method of implementing custom C2 channels has already been done before, as seen in [GraphStrike](https://github.com/RedSiege/GraphStrike). 

However, GraphStrike's implementation is still quite tied to the HTTP protocol itself. The goal of this repo is to provide an easy to use, modify and extend template for implementing any custom channel, HTTP or otherwise, with little modification to the surrounding code. All the user needs to modify is the ```customCallback``` function to perform the following things:

1. transmit the base64 blob (its only argument) out via any means necessary
2. write it to a char*
3. return that char*

and modify the ```handleCallback()``` function in broker.py to do the following:

1. receive callbacks
2. call process_encoded_request(your callback data goes here)
3. send responses back.

Thats it.

The PoC in the customCallback function in the hook.c currently does the following:

1. write the base64 blob to a file, request.txt
2. waits 500ms
3. reads the response from a file response.txt
4. returns the file contents

The PoC in the handleCallback function in the broker.py currently does the following:

1. reads callback from request.txt
2. calls ```process_encoded_request(encoded_request)```
3. writes the response to response.txt

## Usage
the hook.c, hash.h and hook.h files are rough templates, but they can be dropped into [Crystal kit](https://github.com/rasta-mouse/Crystal-Kit) to be used as is as a PoC. Place them into the udrl/src folder, replacing the existing copies. tcg.h is unchanged (from Raphael Mudge's tradecraft garden)

Note that evasion capabilities such as the Draugr implementation and sleep masking have been removed from the hook.c to keep this codebase clean and portable. If you wish to keep those features, you can add them back from the original copies in Crystal kit.

## Credits and references
- https://github.com/rasta-mouse/Crystal-Kit (Original template for dev and testing) 
- https://github.com/RedSiege/GraphStrike (IAT hooking to implement a Graph channel)
- https://github.com/benheise/TitanLdr (IAT hooking to implement DoH)
- https://tradecraftgarden.org/ (framework used for crystal kit, and by extension this)

Yes I used an LLM to write some of the code and comments, nobody likes writing docs or writing boilerplate json parsing in C from scratch.



