SHA256
======

Julia module for creating cryptographic hashes using the SHA-256 algorithm. Developed using [documentation](http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf) of the SHA256 algorithm.

___

Examples:

    julia> using sha256

    julia> hash("abc")
    8-element Array{Uint32,1}:
     0xba7816bf
     0x8f01cfea
     0x414140de
     0x5dae2223
     0xb00361a3
     0x96177a9c
     0xb410ff61
     0xf20015ad

    julia> hash("abc",1)
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

