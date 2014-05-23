module SHA256

export hash

const global_K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

function right_rotation(x::Uint32, n)
	(x >>> n) | ( x << (32 - n))
end	

function ch(x::Uint32,y::Uint32,z::Uint32) 
	(x & y) $ (~x & z)  
end

function maj(x::Uint32,y::Uint32,z::Uint32) 
	(x & y) $ (x & z) $ (y & z)  
end

function Sigma0(x::Uint32)
	right_rotation(x, 2) $ right_rotation(x, 13) $ right_rotation(x, 22)
end

function Sigma1(x::Uint32)
	right_rotation(x, 6) $ right_rotation(x, 11) $ right_rotation(x, 25)
end

function sigma0(x::Uint32)
	right_rotation(x, 7) $ right_rotation(x, 18) $ >>(x, 3)
end

function sigma1(x::Uint32)
	right_rotation(x, 17) $ right_rotation(x, 19) $ >>(x, 10)
end

function preprocessing(input::ASCIIString)
	message_in = input.data

	msg_count = length(message_in)
	msg_bits = msg_count * 8
	appended_zero_bytes = mod(448 - (msg_bits + 1), 512)
	message_array = vcat(message_in, [0x80], zeros(Uint8, ifloor((appended_zero_bytes + 1) / 8) - 1),
						reverse(reinterpret(Uint8, [msg_bits])))
	n_blocks = iceil(length(message_array) / 64)

	output = zeros(Uint32, 16 * n_blocks)

	for i in 1:(16 * n_blocks)
		temp::Uint32 = 0
		for j in 1:4
			temp <<= 8 
			temp |= message_array[4 * (i - 1) + j]
		end
		output[i] = temp
	end
	output
end

function expand_message(msg_in)
	W = Array(Uint32, 64)
	W[1:16] = msg_in
	for j=17:64
		W[j] = sigma1(W[j-2]) + W[j-7] + sigma0(W[j-15]) + W[j-16]
	end
	W
end

function compress(hashes, W)
	a, b, c, d, e, f, g, h = hashes

	for i = 1:64
		T1::Uint32 = h + Sigma1(e) + ch(e,f,g) + global_K[i] + W[i]
		T2::Uint32 = Sigma0(a) + maj(a,b,c)
		h = g
		g = f
		f = e
		e::Uint32 = d + T1
		d = c
		c = b
		b = a
		a::Uint32 = T1 + T2
	end

	[a, b, c, d, e, f, g, h]
end

function hash(input_string::ASCIIString)

	message_blocks = preprocessing(input_string)
	n_blocks = iceil(length(message_blocks) / 16)

	current_hash = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

	for i = 1:n_blocks
		expanded_msg = expand_message(message_blocks[((i - 1) * 16 + 1):(16 * i)])
		current_hash[:] += compress(current_hash, expanded_msg)
	end

	current_hash
end	

function hash(input_string::ASCIIString, flag::Int)
	join(map(num2hex, hash(input_string)))
end

end # End of module
