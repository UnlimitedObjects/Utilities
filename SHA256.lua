local Constants = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function Hexadecimal(String)
	return (string.gsub(String, ".", function(Char)
		return string.format("%02x", string.byte(Char))
	end))
end

local function NumberToBytes(x, y)
	local String = ""
	
	for Idx = 1, y do
		local Remainder = x % 256
		String = string.char(Remainder) .. String
		x = (x - Remainder) / 256
	end
	
	return String
end

local function BytesToNumber(x, y)
	local Number = 0
	
	for Idx = y, y + 3 do
		Number = Number * 256 + string.byte(x, Idx)
	end
	
	return Number
end

local function PreProcess(Message, Length)
	local Extra = 64 - ((Length + 9) % 64)
	Length = NumberToBytes(8 * Length, 8)
	Message = Message .. "\128" .. string.rep("\0", Extra) .. Length
	
	return Message
end

local function ProcessBlock(Message, Offset, Hash)
	local W = {}
	
	for Idx = 1, 16 do
		W[Idx] = BytesToNumber(Message, Offset + (Idx - 1) * 4)
	end
	
	for Idx = 17, 64 do
		local S0 = bit32.bxor(bit32.rrotate(W[Idx - 15], 7), bit32.rrotate(W[Idx - 15], 18), bit32.rshift(W[Idx - 15], 3))
		local S1 = bit32.bxor(bit32.rrotate(W[Idx - 2], 17), bit32.rrotate(W[Idx - 2], 19), bit32.rshift(W[Idx - 2], 10))
		W[Idx] = W[Idx - 16] + S0 + W[Idx - 7] + S1
	end
	
	local A, B, C, D, E, F, G, H = table.unpack(Hash)
	
	for Idx = 1, 64 do
		local S0 = bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22))
		local MAJ = bit32.bxor(bit32.band(A, B), bit32.band(A, C), bit32.band(B, C))
		local T2 = S0 + MAJ
		local S1 = bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25))
		local CH = bit32.bxor(bit32.band(E, F), bit32.band(bit32.bnot(E), G))
		local T1 = H + S1 + CH + Constants[Idx] + W[Idx]
		
		H, G, F, E, D, C, B, A = G, F, E, D + T1, C, B, A, T1 + T2
	end
	
	Hash[1] = bit32.band(Hash[1] + A)
	Hash[2] = bit32.band(Hash[2] + B)
	Hash[3] = bit32.band(Hash[3] + C)
	Hash[4] = bit32.band(Hash[4] + D)
	Hash[5] = bit32.band(Hash[5] + E)
	Hash[6] = bit32.band(Hash[6] + F)
	Hash[7] = bit32.band(Hash[7] + G)
	Hash[8] = bit32.band(Hash[8] + H)
end

local function SHA256(String, Hash)
	String = PreProcess(String, #String)
	
	for Idx = 1, #String, 64 do
		ProcessBlock(String, Idx, Hash)
	end
	
	return Hexadecimal(NumberToBytes(Hash[1], 4) .. NumberToBytes(Hash[2], 4) .. NumberToBytes(Hash[3], 4) .. NumberToBytes(Hash[4], 4) .. NumberToBytes(Hash[5], 4) .. NumberToBytes(Hash[6], 4) .. NumberToBytes(Hash[7], 4) .. NumberToBytes(Hash[8], 4))
end
